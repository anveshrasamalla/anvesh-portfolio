package com.mnt.axp.common.core.services.impl;

import com.google.gson.JsonObject;
import com.mnt.axp.common.core.models.form.Container;
import com.mnt.axp.common.core.models.form.FormInput;
import com.mnt.axp.common.core.services.api.SfmcService;
import com.mnt.axp.common.core.utils.ApiClient;
import com.mnt.axp.common.core.utils.FormHelper;
import com.mnt.axp.common.core.utils.Recaptcha;
import org.apache.commons.lang3.StringUtils;
import org.apache.sling.api.request.RequestParameter;
import org.apache.sling.api.request.RequestParameterMap;
import org.apache.sling.api.resource.*;
import org.apache.sling.xss.XSSFilter;
import org.json.JSONObject;
import org.osgi.service.component.annotations.*;
import org.osgi.service.metatype.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.ZonedDateTime;
import java.util.*;

@Component(
        service = SfmcService.class,
        configurationPolicy = ConfigurationPolicy.REQUIRE,
        immediate = true
)
@Designate(ocd = SfmcServiceImpl.Config.class)
public class SfmcServiceImpl implements SfmcService {

    private static final Logger LOG = LoggerFactory.getLogger(SfmcServiceImpl.class);

    @ObjectClassDefinition(
            name = "AXP SFMC Integration Service",
            description = "Handles Salesforce Marketing Cloud API calls and reCAPTCHA validation"
    )
    public @interface Config {
        @AttributeDefinition(name = "Auth Base URL") String sfmc_auth_base();
        @AttributeDefinition(name = "REST Base URL") String sfmc_rest_base();
        @AttributeDefinition(name = "Client ID") String sfmc_client_id();
        @AttributeDefinition(name = "Client Secret") String sfmc_client_secret();
        @AttributeDefinition(name = "Account ID") String sfmc_account_id();
        @AttributeDefinition(name = "Default Data Extension Key") String sfmc_default_de_key();
        @AttributeDefinition(name = "reCAPTCHA Secret Key") String greCAPTCHA_secretKey();
        @AttributeDefinition(name = "Timeout (ms)", deflt = "10000") int timeout_ms();
        @AttributeDefinition(name = "Enable Debug Logs", deflt = "false") boolean debug_logs();
    }

    private String authBase, restBase, clientId, clientSecret, accountId, defaultDeKey, recaptchaSecret;
    private int timeout;
    private boolean debug;

    @Reference private XSSFilter xssFilter;
    @Reference private ResourceResolverFactory rrf;
    private ApiClient apiClient = new ApiClient();

    public void setApiClient(ApiClient apiClient) { this.apiClient = apiClient; }

    @Activate
    @Modified
    protected void activate(Config cfg) {
        this.authBase = strip(cfg.sfmc_auth_base());
        this.restBase = strip(cfg.sfmc_rest_base());
        this.clientId = cfg.sfmc_client_id();
        this.clientSecret = cfg.sfmc_client_secret();
        this.accountId = cfg.sfmc_account_id();
        this.defaultDeKey = cfg.sfmc_default_de_key();
        this.recaptchaSecret = cfg.greCAPTCHA_secretKey();
        this.timeout = cfg.timeout_ms();
        this.debug = cfg.debug_logs();
        LOG.info("✅ SFMC Service Activated | Auth={} | REST={} | Timeout={}ms", authBase, restBase, timeout);
    }

    private String strip(String s) {
        return s != null && s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    @Override
    public SalesforceResponse validateAndSubmitForm(
            List<String> searchPaths,
            String formResourceType,
            String urlParameter,
            RequestParameterMap rpm) throws IOException {

        SalesforceResponse resp = new SalesforceResponse();
        String submissionId = UUID.randomUUID().toString();
        RequestParameter formIdParam = rpm.getValue("aemformid");
        String formIdStr = formIdParam != null ? formIdParam.getString() : "";

        if (StringUtils.isBlank(formIdStr) || !formIdStr.matches("^[0-9\\-]*$")) {
            resp.message = "Invalid or missing Form ID.";
            LOG.error("❌ Invalid Form ID {}", formIdStr);
            return resp;
        }

        Map<String, Object> svcParams = Map.of(ResourceResolverFactory.SUBSERVICE, "mtb-search-user");
        try (ResourceResolver rr = rrf.getServiceResourceResolver(svcParams)) {
            double score = verifyCaptcha(recaptchaSecret, rpm);
            resp.score = score;
            LOG.info("🔐 reCAPTCHA Score={}", score);

            Resource formRes = FormHelper.findForm(Integer.parseInt(formIdStr), searchPaths, formResourceType, rr);
            Container formModel = formRes != null ? formRes.adaptTo(Container.class) : null;
            if (formModel == null) {
                resp.message = "Form not found.";
                LOG.error("❌ Form not found {}", formIdStr);
                return resp;
            }

            Map<String, String> validParams = new LinkedHashMap<>();
            validParams.put("AEMSubmissionID", submissionId);
            validParams.put("CaptchaScore", String.valueOf(score));
            validParams.put("FormId", formModel.getSalesforceFormId());
            validParams.put("_deExternalKey", StringUtils.defaultIfBlank(formModel.getSalesforceBucket(), defaultDeKey));
            validParams.putAll(FormHelper.getHiddenFields(formModel, rpm));
            validParams.putAll(FormHelper.getPrivateFields(formModel));

            List<FormInput> inputs = FormHelper.findFormInputs(formRes);
            FormHelper.Parameters p = FormHelper.getAllInputs(inputs, rpm);
            validParams.putAll(p.getValid());
            resp.invalidField.addAll(p.getInvalid());
            if (!resp.invalidField.isEmpty()) {
                resp.message = "Invalid input fields.";
                LOG.warn("⚠️ Invalid fields {}", resp.invalidField);
                return resp;
            }

            JSONObject payload = buildSfmcPayload(validParams);
            String token = authenticate();
            boolean ok = postToDataExtension(token, validParams.get("_deExternalKey"), payload);

            resp.message = ok ? "Successfully updated SFMC Data Extension."
                    : "Failed to submit form to SFMC.";
            resp.error = !ok;
            LOG.info(ok ? "✅ SFMC Submission Success" : "❌ SFMC Submission Failed");

        } catch (LoginException e) {
            LOG.error("Service user login failed", e);
            resp.message = "Unable to access AEM service user.";
        }
        return resp;
    }

    protected String authenticate() {
        JsonObject body = new JsonObject();
        body.addProperty("grant_type", "client_credentials");
        body.addProperty("client_id", clientId);
        body.addProperty("client_secret", clientSecret);
        body.addProperty("account_id", accountId);
        JsonObject resp = apiClient.makeApiCall("POST", authBase + "/v2/token", body, Collections.emptyMap());
        if (resp.has("access_token")) return resp.get("access_token").getAsString();
        throw new RuntimeException("SFMC Auth failed");
    }

    protected boolean postToDataExtension(String token, String deKey, JSONObject payload) {
        String url = restBase + "/data/v1/async/dataextensions/key:" + deKey + "/rows";
        Map<String, String> headers = Map.of("Authorization", "Bearer " + token);
        JsonObject body = new JsonObject();
        body.add("items", new com.google.gson.JsonParser()
                .parse(payload.getJSONArray("items").toString()).getAsJsonArray());
        JsonObject resp = apiClient.makeApiCall("POST", url, body, headers);
        return !resp.has("error");
    }

    protected double verifyCaptcha(String secret, RequestParameterMap rpm) {
        try {
            HttpServletRequest req = rpm.getRequest();
            String token = rpm.containsKey("g-recaptcha-response") ? rpm.getValue("g-recaptcha-response").getString() : "";
            return Recaptcha.isCaptchaValid(secret, "", token, req);
        } catch (Exception e) {
            LOG.error("Captcha verification error", e);
            return 0.0;
        }
    }

    protected JSONObject buildSfmcPayload(Map<String, String> p) {
        JSONObject item = new JSONObject();
        String email = p.getOrDefault("Email", "testing@example.com");
        item.put("SubscriberKey", email);
        item.put("EmailAddress", email);
        item.put("FormID", p.get("FormId"));
        item.put("AEMSubmissionID", p.get("AEMSubmissionID"));
        item.put("CaptchaScore", p.get("CaptchaScore"));
        item.put("FirstName", p.getOrDefault("FirstName", ""));
        item.put("LastName", p.getOrDefault("LastName", ""));
        item.put("State", p.getOrDefault("State", ""));
        item.put("MessageBody", "Submitted from AEM at " + ZonedDateTime.now());
        JSONObject payload = new JSONObject();
        payload.put("items", new org.json.JSONArray().put(item));
        return payload;
    }
}

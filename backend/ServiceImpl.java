package com.mnt.axp.common.core.services.impl;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.mnt.axp.common.core.services.api.SfmcService;
import com.mnt.axp.common.core.utils.ApiClient;
import com.mnt.axp.common.core.utils.Recaptcha;
import org.apache.commons.lang3.StringUtils;
import org.apache.sling.api.request.RequestParameter;
import org.apache.sling.api.request.RequestParameterMap;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.json.JSONArray;
import org.json.JSONObject;

@Component(
        service = SfmcService.class,
        immediate = true
)
@Designate(ocd = SfmcServiceImpl.Config.class)
public class SfmcServiceImpl implements SfmcService {

    private static final Logger LOG = LoggerFactory.getLogger(SfmcServiceImpl.class);

    @ObjectClassDefinition(name = "AXP SFMC Integration (Option B)")
    public @interface Config {
        @AttributeDefinition(name = "SFMC Auth Base URL")
        String sfmc_auth_base();
        @AttributeDefinition(name = "SFMC REST Base URL")
        String sfmc_rest_base();
        @AttributeDefinition(name = "SFMC Client ID")
        String sfmc_client_id();
        @AttributeDefinition(name = "SFMC Client Secret")
        String sfmc_client_secret();
        @AttributeDefinition(name = "SFMC Account ID")
        String sfmc_account_id();
        @AttributeDefinition(name = "Default Data Extension Key")
        String sfmc_default_de_key();

        @AttributeDefinition(name = "reCAPTCHA Secret Key")
        String recaptcha_secret();

        @AttributeDefinition(name = "Enable Debug Logs", deflt = "false")
        boolean debug_logs();
    }

    // OSGi config values
    private String authBase;
    private String restBase;
    private String clientId;
    private String clientSecret;
    private String accountId;
    private String defaultDeKey;
    private String recaptchaSecret;
    private boolean debug;

    // Utilities
    private ApiClient apiClient = new ApiClient(); // your existing HTTP helper

    /** For testing/injection if needed */
    public void setApiClient(ApiClient apiClient) { this.apiClient = apiClient; }

    @Activate
    @Modified
    protected void activate(Config c) {
        this.authBase       = trim(c.sfmc_auth_base());
        this.restBase       = trim(c.sfmc_rest_base());
        this.clientId       = c.sfmc_client_id();
        this.clientSecret   = c.sfmc_client_secret();
        this.accountId      = c.sfmc_account_id();
        this.defaultDeKey   = c.sfmc_default_de_key();
        this.recaptchaSecret= c.recaptcha_secret();
        this.debug          = c.debug_logs();

        LOG.info("SFMC Service ready. AUTH={}, REST={}, DE={}, Debug={}",
                authBase, restBase, defaultDeKey, debug);
    }

    private String trim(String s) {
        return (s != null && s.endsWith("/")) ? s.substring(0, s.length() - 1) : s;
    }

    // ---------------- Main ----------------

    @Override
    public SalesforceResponse submitToSfmc(RequestParameterMap params, HttpServletRequest request) throws IOException {
        SalesforceResponse out = new SalesforceResponse();
        final String submissionId = UUID.randomUUID().toString();

        // reCAPTCHA score (uses your utility)
        double score = getCaptchaScore(params, request);
        out.score = score;
        LOG.info("reCAPTCHA score={}", score);

        // Build SFMC payload from request params
        JSONObject payload = buildPayload(params, submissionId, score);

        // Auth then post
        String token = getToken();
        boolean ok = postRows(token, payload);

        out.error = !ok;
        out.message = ok ? "Successfully submitted to SFMC." : "SFMC submission failed.";
        return out;
    }

    // ---------------- Helpers ----------------

    private double getCaptchaScore(RequestParameterMap params, HttpServletRequest req) {
        try {
            RequestParameter p = params.getValue("g-recaptcha-response");
            String token = (p != null) ? p.getString() : "";
            if (StringUtils.isBlank(token)) {
                LOG.warn("Missing g-recaptcha-response");
                return 0.0d;
            }
            // Your Recaptcha utility signature: (secretKey, publicKey, token, request)
            return Recaptcha.isCaptchaValid(recaptchaSecret, "", token, req);
        } catch (Exception e) {
            LOG.error("reCAPTCHA validation error", e);
            return 0.0d;
        }
    }

    private String getToken() {
        String url = authBase + "/v2/token";
        JsonObject body = new JsonObject();
        body.addProperty("grant_type", "client_credentials");
        body.addProperty("client_id", clientId);
        body.addProperty("client_secret", clientSecret);
        body.addProperty("account_id", accountId);

        JsonObject res = apiClient.makeApiCall("POST", url, body, Collections.<String,String>emptyMap());
        if (res != null && res.has("access_token")) {
            String token = res.get("access_token").getAsString();
            if (debug) LOG.debug("SFMC auth success. token length={}", token != null ? token.length() : 0);
            return token;
        }
        throw new RuntimeException("SFMC auth failed: " + String.valueOf(res));
    }

    private boolean postRows(String token, JSONObject payload) {
        String url = restBase + "/data/v1/async/dataextensions/key:" + defaultDeKey + "/rows";

        Map<String,String> headers = new HashMap<String,String>();
        headers.put("Authorization", "Bearer " + token);
        headers.put("Content-Type", "application/json");

        // Convert org.json -> gson
        JsonObject gsonPayload = new JsonParser().parse(payload.toString()).getAsJsonObject();
        JsonObject res = apiClient.makeApiCall("POST", url, gsonPayload, headers);

        if (debug) LOG.debug("SFMC DE response: {}", String.valueOf(res));
        return !(res == null || res.has("error"));
    }

    private JSONObject buildPayload(RequestParameterMap p, String submissionId, double score) {
        JSONObject item = new JSONObject();
        String email = getParam(p, "Email", "unknown@example.com");

        item.put("SubscriberKey", email);
        item.put("EmailAddress", email);
        item.put("FirstName", getParam(p, "FirstName", ""));
        item.put("LastName", getParam(p, "LastName", ""));
        item.put("Phone", getParam(p, "Phone", ""));
        item.put("City", getParam(p, "City", ""));
        item.put("State", getParam(p, "State", ""));
        item.put("Zip", getParam(p, "Zip", ""));
        item.put("Country", getParam(p, "Country", ""));

        item.put("FormID", getParam(p, "FormID", "unknown"));
        item.put("AEMSubmissionID", submissionId);
        item.put("CaptchaScore", score);
        item.put("TimeStamp", ZonedDateTime.now().toString());
        item.put("MessageBody", "Submitted via AEM " + ZonedDateTime.now());

        JSONArray items = new JSONArray();
        items.put(item);

        JSONObject payload = new JSONObject();
        payload.put("items", items);
        return payload;
    }

    private String getParam(RequestParameterMap p, String key, String def) {
        return p.containsKey(key) ? p.getValue(key).getString() : def;
    }
}

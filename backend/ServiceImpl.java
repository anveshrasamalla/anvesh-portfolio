package com.mnt.axp.common.core.services.impl;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.mnt.axp.common.core.services.api.SfmcService;
import com.mnt.axp.common.core.utils.ApiClient;
import com.mnt.axp.common.core.utils.Recaptcha;
import org.apache.commons.lang3.StringUtils;
import org.apache.sling.api.request.RequestParameter;
import org.apache.sling.api.request.RequestParameterMap;
import org.apache.sling.xss.XSSFilter;
import org.json.JSONArray;
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

    @ObjectClassDefinition(name = "AXP SFMC Integration Service (Simplified)")
    public @interface Config {
        @AttributeDefinition(name = "SFMC Auth Base URL")
        String sfmc_auth_base();

        @AttributeDefinition(name = "SFMC REST Base URL")
        String sfmc_rest_base();

        @AttributeDefinition(name = "SFMC Client ID")     String sfmc_client_id();
        @AttributeDefinition(name = "SFMC Client Secret") String sfmc_client_secret();
        @AttributeDefinition(name = "SFMC Account ID")    String sfmc_account_id();
        @AttributeDefinition(name = "Default Data Extension Key") String sfmc_default_de_key();

        @AttributeDefinition(name = "reCAPTCHA Secret Key") String recaptcha_secret();
        @AttributeDefinition(name = "Enable Debug Logs", deflt = "false") boolean debug_logs();
    }

    // Config values
    private String authBase;
    private String restBase;
    private String clientId;
    private String clientSecret;
    private String accountId;
    private String defaultDeKey;
    private String recaptchaSecret;
    private boolean debug;

    @Reference private XSSFilter xss;
    private ApiClient api = new ApiClient();

    @Activate @Modified
    protected void activate(Config c) {
        authBase = trim(c.sfmc_auth_base());
        restBase = trim(c.sfmc_rest_base());
        clientId = c.sfmc_client_id();
        clientSecret = c.sfmc_client_secret();
        accountId = c.sfmc_account_id();
        defaultDeKey = c.sfmc_default_de_key();
        recaptchaSecret = c.recaptcha_secret();
        debug = c.debug_logs();
        LOG.info("SFMC Service active. DE={} AuthBase={}", defaultDeKey, authBase);
    }

    private String trim(String s) {
        return s != null && s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    // ---------- Main ----------
    public SalesforceResponse submitToSfmc(RequestParameterMap params, HttpServletRequest req) throws IOException {
        SalesforceResponse out = new SalesforceResponse();
        String submissionId = UUID.randomUUID().toString();

        double score = getCaptchaScore(params, req);
        out.score = score;
        LOG.info("reCAPTCHA score = {}", score);

        JSONObject payload = buildPayload(params, submissionId, score);
        String token = getToken();

        boolean ok = postToSfmc(token, payload);
        out.error = !ok;
        out.message = ok ? "✅ Form submitted to SFMC" : "❌ SFMC submission failed";
        return out;
    }

    // ---------- Helpers ----------
    private double getCaptchaScore(RequestParameterMap p, HttpServletRequest req) {
        try {
            RequestParameter rp = p.getValue("g-recaptcha-response");
            String token = rp != null ? rp.getString() : "";
            if (StringUtils.isBlank(token)) return 0.0;
            return Recaptcha.isCaptchaValid(recaptchaSecret, "", token, req);
        } catch (Exception e) {
            LOG.error("reCAPTCHA error", e);
            return 0.0;
        }
    }

    private String getToken() {
        JsonObject body = new JsonObject();
        body.addProperty("grant_type", "client_credentials");
        body.addProperty("client_id", clientId);
        body.addProperty("client_secret", clientSecret);
        body.addProperty("account_id", accountId);
        JsonObject res = api.makeApiCall("POST", authBase + "/v2/token", body, Collections.<String,String>emptyMap());
        if (res != null && res.has("access_token")) return res.get("access_token").getAsString();
        throw new RuntimeException("SFMC Auth failed → " + res);
    }

    private boolean postToSfmc(String token, JSONObject payload) {
        String url = restBase + "/data/v1/async/dataextensions/key:" + defaultDeKey + "/rows";
        Map<String,String> headers = new HashMap<String,String>();
        headers.put("Authorization", "Bearer " + token);

        JsonObject gsonPayload = new JsonParser().parse(payload.toString()).getAsJsonObject();
        JsonObject res = api.makeApiCall("POST", url, gsonPayload, headers);

        if (res == null) return false;
        return !res.has("error");
    }

    private JSONObject buildPayload(RequestParameterMap p, String submissionId, double score) {
        JSONObject item = new JSONObject();
        String email = getValue(p, "Email", "unknown@example.com");
        item.put("SubscriberKey", email);
        item.put("EmailAddress", email);
        item.put("FirstName", getValue(p, "FirstName", ""));
        item.put("LastName", getValue(p, "LastName", ""));
        item.put("Phone", getValue(p, "Phone", ""));
        item.put("State", getValue(p, "State", ""));
        item.put("CaptchaScore", score);
        item.put("AEMSubmissionID", submissionId);
        item.put("FormID", getValue(p, "FormID", "unknown"));
        item.put("TimeStamp", ZonedDateTime.now().toString());
        item.put("MessageBody", "Submitted via AEM at " + ZonedDateTime.now());
        JSONObject payload = new JSONObject();
        payload.put("items", new JSONArray().put(item));
        return payload;
    }

    private String getValue(RequestParameterMap p, String k, String d) {
        return p.containsKey(k) ? p.getValue(k).getString() : d;
    }
}

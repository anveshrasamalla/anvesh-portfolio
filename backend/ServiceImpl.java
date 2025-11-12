package com.mnt.axp.common.core.services.impl;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.mnt.axp.common.core.services.api.SfmcService;
import com.mnt.axp.common.core.utils.ApiClient;
import com.mnt.axp.common.core.utils.Recaptcha;
import org.apache.sling.api.request.RequestParameter;
import org.apache.sling.api.request.RequestParameterMap;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Production-ready SFMC integration:
 *  - Direct calls to SFMC (no proxy, no trust-all)
 *  - Uses existing ApiClient + Recaptcha utilities
 *  - All config via OSGi
 *  - Mandatory fields ensured: AEMSubmissionID, TimeStamp, FormID, MessageBody, CaptchaScore
 */
@Component(service = SfmcService.class, immediate = true)
@Designate(ocd = SfmcServiceImpl.Config.class)
public class SfmcServiceImpl implements SfmcService {

    private static final Logger LOG = LoggerFactory.getLogger(SfmcServiceImpl.class);

    @ObjectClassDefinition(name = "AXP SFMC Integration (Prod Ready)")
    public @interface Config {
        @AttributeDefinition(name = "SFMC Auth Base",
                description = "e.g., https://<tenant>.auth.marketingcloudapis.com")
        String auth_base();

        @AttributeDefinition(name = "SFMC REST Base",
                description = "e.g., https://<tenant>.rest.marketingcloudapis.com")
        String rest_base();

        @AttributeDefinition(name = "SFMC Client ID") String client_id();
        @AttributeDefinition(name = "SFMC Client Secret") String client_secret();
        @AttributeDefinition(name = "SFMC Account ID") String account_id();

        @AttributeDefinition(name = "reCAPTCHA Secret Key",
                description = "Server-side secret used to verify v3 token")
        String recaptcha_secret();

        @AttributeDefinition(name = "reCAPTCHA Site Key (optional)",
                description = "Public site key; not required for server verification")
        String recaptcha_site_key();
    }

    private String authBase;
    private String restBase;
    private String clientId;
    private String clientSecret;
    private String accountId;
    private String recaptchaSecret;
    private String recaptchaSiteKey;

    private final ApiClient apiClient = new ApiClient();

    // Minimal internal skip list
    private static final Set<String> INTERNAL_SKIP = new HashSet<String>(Arrays.asList(
            "g-recaptcha-response",
            ":cq_csrf_token",
            "_charset_"
    ));

    private static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ofPattern("MM/dd/yyyy HH:mm").withZone(ZoneId.systemDefault());

    @Activate @Modified
    protected void activate(Config cfg) {
        authBase         = trim(cfg.auth_base());
        restBase         = trim(cfg.rest_base());
        clientId         = trim(cfg.client_id());
        clientSecret     = trim(cfg.client_secret());
        accountId        = trim(cfg.account_id());
        recaptchaSecret  = trim(cfg.recaptcha_secret());
        recaptchaSiteKey = trim(cfg.recaptcha_site_key());

        LOG.info("SFMC service ready. authBase={}, restBase={}", authBase, restBase);
    }

    private String trim(String s) { return s == null ? "" : s.trim(); }

    @Override
    public SalesforceResponse submitToSfmc(RequestParameterMap params, HttpServletRequest request) throws IOException {
        SalesforceResponse out = new SalesforceResponse();

        // 1) reCAPTCHA score
        double score = validateCaptcha(params, request);
        out.score = score;
        LOG.debug("reCAPTCHA score: {}", score);

        // 2) Build payload (copy strings + enforce minimal fields)
        String submissionId = UUID.randomUUID().toString();
        JsonObject payload = buildPayload(params, submissionId, score);

        // 3) Get OAuth token
        String token = getToken();
        if (token == null) {
            out.message  = "Auth failed: access_token missing";
            out.error    = true;
            out.httpCode = 500;
            return out;
        }

        // 4) Pick DE key (front-end sends 'de_key'); fallback allowed
        String deKey = getParam(params, "de_key", "AEM-FORM-ENDPNT-INTRNL-TEST");
        String dePath = "/data/v1/async/dataextensions/key:" + deKey + "/rows";

        // 5) POST rows
        PostOutcome po = postToDE(token, dePath, payload);
        out.message   = po.message;
        out.error     = po.error;
        out.httpCode  = po.httpCode;
        out.requestId = po.requestId;

        return out;
    }

    // ---------- helpers ----------

    private double validateCaptcha(RequestParameterMap p, HttpServletRequest req) {
        try {
            RequestParameter rp = p.getValue("g-recaptcha-response");
            String token = (rp != null) ? rp.getString() : "";
            if (token == null || token.trim().isEmpty()) {
                LOG.warn("g-recaptcha-response missing");
                return 0.0;
            }
            // Use your existing Recaptcha utility
            return Recaptcha.isCaptchaValid(recaptchaSecret, recaptchaSiteKey, token, req);
        } catch (Exception e) {
            LOG.error("reCAPTCHA validation error", e);
            return 0.0;
        }
    }

    private JsonObject buildPayload(RequestParameterMap p, String submissionId, double score) {
        JsonObject item = new JsonObject();

        // Copy simple string params, skip internals
        for (Map.Entry<String, RequestParameter[]> e : p.entrySet()) {
            String k = e.getKey();
            if (INTERNAL_SKIP.contains(k)) continue;
            RequestParameter[] rps = e.getValue();
            if (rps != null && rps.length > 0) {
                item.addProperty(k, rps[0].getString());
            }
        }

        // Enforce mandatory fields
        if (!item.has("AEMSubmissionID")) item.addProperty("AEMSubmissionID", submissionId);
        if (!item.has("TimeStamp"))       item.addProperty("TimeStamp", TS_FMT.format(java.time.Instant.now()));
        if (!item.has("FormID"))          item.addProperty("FormID", getParam(p, "FormID", ""));
        if (!item.has("MessageBody"))     item.addProperty("MessageBody", getParam(p, "MessageBody", ""));
        item.addProperty("CaptchaScore", String.valueOf(score));

        // Wrap under "items": [...]
        JsonArray arr = new JsonArray();
        arr.add(item);
        JsonObject payload = new JsonObject();
        payload.add("items", arr);

        LOG.debug("Payload to SFMC: {}", payload);
        return payload;
    }

    private String getParam(RequestParameterMap p, String key, String def) {
        RequestParameter rp = p.getValue(key);
        return rp != null ? rp.getString() : def;
    }

    private String getToken() {
        JsonObject req = new JsonObject();
        req.addProperty("grant_type", "client_credentials");
        req.addProperty("client_id",     clientId);
        req.addProperty("client_secret", clientSecret);
        req.addProperty("account_id",    accountId);

        String url = authBase + "/v2/token";
        JsonObject j = apiClient.makeApiCall("POST", url, req, java.util.Collections.<String,String>emptyMap());

        if (j == null || !j.has("access_token")) {
            LOG.error("Auth failed. Response: {}", (j == null ? "null" : j.toString()));
            return null;
        }
        return j.get("access_token").getAsString();
    }

    private PostOutcome postToDE(String accessToken, String dePath, JsonObject payload) {
        Map<String,String> headers = new HashMap<String,String>();
        headers.put("Authorization", "Bearer " + accessToken);

        String url = restBase + dePath;
        JsonObject j = apiClient.makeApiCall("POST", url, payload, headers);

        PostOutcome out = new PostOutcome();
        // Success case from SFMC async insert → 202 + { "requestId": "..." }
        if (j != null && j.has("requestId")) {
            out.httpCode  = 202;
            out.error     = false;
            out.requestId = j.get("requestId").getAsString();
            out.message   = j.toString();
        } else {
            out.httpCode  = 500;
            out.error     = true;
            out.requestId = "";
            out.message   = (j == null) ? "Null response from SFMC" : j.toString();
        }
        return out;
    }

    private static class PostOutcome {
        String  requestId;
        String  message;
        boolean error;
        int     httpCode;
    }
}

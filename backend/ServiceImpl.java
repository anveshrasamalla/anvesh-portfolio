package com.mnt.axp.common.core.services.impl;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.mnt.axp.common.core.services.api.SfmcService;
import com.mnt.axp.common.core.utils.ApiClient;
import com.mnt.axp.common.core.utils.Recaptcha;
import org.apache.sling.api.request.RequestParameterMap;
import org.json.JSONArray;
import org.json.JSONObject;
import org.osgi.service.component.annotations.*;
import org.osgi.service.metatype.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.*;

/**
 * AXP Salesforce Marketing Cloud Service Implementation
 *
 * Flow:
 *  1. Validate reCAPTCHA
 *  2. Get OAuth token
 *  3. Build payload (required fields only)
 *  4. Post to Data Extension (async)
 *  5. Return {message, error, httpCode, requestId}
 */
@Component(service = SfmcService.class, immediate = true)
@Designate(ocd = SfmcServiceImpl.Config.class)
public class SfmcServiceImpl implements SfmcService {

    private static final Logger LOG = LoggerFactory.getLogger(SfmcServiceImpl.class);

    @ObjectClassDefinition(name = "AXP SFMC Configuration")
    public @interface Config {
        String sfmc_auth_base();
        String sfmc_rest_base();
        String sfmc_client_id();
        String sfmc_client_secret();
        String sfmc_account_id();
        String recaptcha_secret();
        boolean debug_logs() default false;
    }

    private String authBase, restBase, clientId, clientSecret, accountId, recaptchaSecret;
    private boolean debug;
    private final ApiClient apiClient = new ApiClient();

    @Activate @Modified
    protected void activate(Config c) {
        authBase        = trim(c.sfmc_auth_base());
        restBase        = trim(c.sfmc_rest_base());
        clientId        = c.sfmc_client_id();
        clientSecret    = c.sfmc_client_secret();
        accountId       = c.sfmc_account_id();
        recaptchaSecret = c.recaptcha_secret();
        debug           = c.debug_logs();
        LOG.info("SFMC Service activated for account={} (debug={})", accountId, debug);
    }

    private String trim(String s) {
        return (s != null && s.endsWith("/")) ? s.substring(0, s.length() - 1) : s;
    }

    @Override
    public SalesforceResponse submitToSfmc(RequestParameterMap params, HttpServletRequest request)
            throws IOException {

        SalesforceResponse res = new SalesforceResponse();
        String submissionId = UUID.randomUUID().toString();

        LOG.info("[SFMC] Submission start: {}", submissionId);

        // 1️⃣ reCAPTCHA validation
        res.score = getCaptchaScore(params, request);
        LOG.debug("[SFMC] reCAPTCHA score={}", res.score);

        // 2️⃣ Build payload
        JSONObject payload = buildPayload(params, submissionId, res.score);
        if (debug) LOG.debug("[SFMC] Payload JSON: {}", payload);

        // 3️⃣ Get OAuth token
        String token;
        try {
            token = getToken();
            LOG.info("[SFMC] Token acquired successfully");
        } catch (Exception e) {
            res.error = true;
            res.httpCode = 500;
            res.message = "Auth failed: " + e.getMessage();
            LOG.error("[SFMC] Auth error", e);
            return res;
        }

        // 4️⃣ Get DE Key
        String deKey = getParam(params, "deKey", "AEM-FORM-ENDPNT-INTRNL-TEST");
        if (deKey.isEmpty()) {
            res.error = true;
            res.httpCode = 400;
            res.message = "Missing Data Extension Key (deKey)";
            return res;
        }

        // 5️⃣ POST to SFMC
        JsonObject response = postToSfmc(token, deKey, payload);

        if (response != null && response.has("requestId")) {
            res.httpCode  = 202;
            res.error     = false;
            res.requestId = response.get("requestId").getAsString();
            res.message   = "Accepted by SFMC";
        } else {
            res.httpCode  = 500;
            res.error     = true;
            res.message   = "Unexpected response";
        }

        LOG.info("[SFMC] Submission complete: status={} reqId={}", res.httpCode, res.requestId);
        return res;
    }

    private double getCaptchaScore(RequestParameterMap params, HttpServletRequest req) {
        try {
            String token = getParam(params, "g-recaptcha-response", "");
            return Recaptcha.isCaptchaValid(recaptchaSecret, "", token, req);
        } catch (Exception e) {
            LOG.warn("[SFMC] reCAPTCHA validation failed: {}", e.getMessage());
            return 0.0;
        }
    }

    private String getToken() {
        String url = authBase + "/v2/token";
        JsonObject body = new JsonObject();
        body.addProperty("grant_type", "client_credentials");
        body.addProperty("client_id", clientId);
        body.addProperty("client_secret", clientSecret);
        body.addProperty("account_id", accountId);

        JsonObject resp = apiClient.makeApiCall("POST", url, body, Collections.emptyMap());
        if (resp != null && resp.has("access_token")) return resp.get("access_token").getAsString();
        throw new RuntimeException("Invalid token response: " + resp);
    }

    private JSONObject buildPayload(RequestParameterMap params, String submissionId, double score) {
        JSONObject item = new JSONObject();
        item.put("AEMSubmissionID", submissionId);
        item.put("TimeStamp", "");
        item.put("FormID", getParam(params, "FormID", "unknown"));
        item.put("MessageBody", getParam(params, "MessageBody", ""));
        item.put("CaptchaScore", score);

        JSONArray items = new JSONArray();
        items.put(item);
        JSONObject root = new JSONObject();
        root.put("items", items);
        return root;
    }

    private String getParam(RequestParameterMap map, String key, String def) {
        return map.containsKey(key) ? map.getValue(key).getString() : def;
    }

    private JsonObject postToSfmc(String token, String deKey, JSONObject payload) {
        String url = restBase + "/data/v1/async/dataextensions/key:" + deKey + "/rows";
        Map<String,String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + token);
        headers.put("Content-Type", "application/json");

        JsonObject body = JsonParser.parseString(payload.toString()).getAsJsonObject();
        JsonObject resp = apiClient.makeApiCall("POST", url, body, headers);

        if (debug) LOG.debug("[SFMC] Raw API response: {}", resp);
        return resp;
    }
}

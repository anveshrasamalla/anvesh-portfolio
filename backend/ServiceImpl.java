package com.mnt.axp.common.core.services.impl;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.mnt.axp.common.core.services.SfmcService;
import com.mnt.axp.common.core.utils.ApiClient;
import com.mnt.axp.common.core.utils.Recaptcha;
import org.apache.commons.lang3.StringUtils;
import org.apache.sling.api.request.RequestParameter;
import org.apache.sling.api.request.RequestParameterMap;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.Instant;
import java.util.*;

@Component(service = SfmcService.class, immediate = true)
@Designate(ocd = SfmcServiceImpl.Config.class)
public class SfmcServiceImpl implements SfmcService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SfmcServiceImpl.class);

    // TODO: update this PID + property name to match your existing repayment / Salesforce config
    private static final String RECAPTCHA_CONFIG_PID = "com.mnt.axp.common.core.services.RepaymentService";
    private static final String RECAPTCHA_SECRET_PROP = "greCAPTCHA_secretKey";

    // Internal fields we do not want in MessageBody
    private static final Set<String> INTERNAL_FIELDS = new HashSet<String>(
            Arrays.asList(
                    "g-recaptcha-response",
                    ":cq_csrf_token",
                    "_charset_",
                    "_successURL",
                    "_errorURL",
                    "MessageBody"
            )
    );

    @ObjectClassDefinition(name = "AXP SFMC Integration")
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

        @AttributeDefinition(name = "Enable Debug Logs")
        boolean debug_logs() default false;
    }

    // OSGi config values
    private String authBase;
    private String restBase;
    private String clientId;
    private String clientSecret;
    private String accountId;
    private String defaultDeKey;
    private boolean debugLogs;

    // Utilities
    private final ApiClient apiClient = new ApiClient();

    @Reference
    private ConfigurationAdmin configurationAdmin;

    @Activate
    protected void activate(Config config) {
        this.authBase = trimTrailingSlash(config.sfmc_auth_base());
        this.restBase = trimTrailingSlash(config.sfmc_rest_base());
        this.clientId = config.sfmc_client_id();
        this.clientSecret = config.sfmc_client_secret();
        this.accountId = config.sfmc_account_id();
        this.defaultDeKey = config.sfmc_default_de_key();
        this.debugLogs = config.debug_logs();

        LOGGER.info("[SFMC] Service activated. authBase={}, restBase={}, defaultDeKey={}, debugLogs={}",
                authBase, restBase, defaultDeKey, debugLogs);
    }

    private String trimTrailingSlash(String value) {
        if (value == null) {
            return null;
        }
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    // ========================================================================
    // Main entry
    // ========================================================================

    @Override
    public SalesforceResponse submitToSfmc(RequestParameterMap params,
                                           HttpServletRequest request) throws IOException {
        SalesforceResponse out = new SalesforceResponse();
        final String submissionId = UUID.randomUUID().toString();
        final String formId = getString(params, "FormID",
                getString(params, "FormId", getString(params, "formId", "")));

        LOGGER.info("[SFMC] New submission. submissionId={}, FormID={}", submissionId, formId);

        // 1) reCAPTCHA score – NEVER blocks SFMC submission
        double score = resolveRecaptchaScore(params, request);
        out.score = score;
        LOGGER.info("[SFMC] reCAPTCHA score (will be sent to SFMC): {}", score);

        // 2) Get OAuth token
        String accessToken = getAccessToken();
        if (StringUtils.isBlank(accessToken)) {
            out.message = "Auth failed: unable to obtain SFMC access token";
            out.error = true;
            out.httpCode = 500;
            LOGGER.error("[SFMC] {}", out.message);
            return out;
        }

        // 3) Determine Data Extension key
        String deKey = getString(params, "DataExtensionKey", defaultDeKey);
        if (StringUtils.isBlank(deKey)) {
            out.message = "Missing DataExtensionKey and no default is configured";
            out.error = true;
            out.httpCode = 400;
            LOGGER.error("[SFMC] {}", out.message);
            return out;
        }

        // 4) Build payload
        JsonObject payload = buildPayload(params, submissionId, formId, score);
        if (debugLogs) {
            LOGGER.debug("[SFMC] Payload for DE {}: {}", deKey, payload);
        }

        // 5) POST to SFMC
        String url = restBase + "/data/v1/async/dataextensions/key:" + deKey + "/rows";
        JsonObject responseJson = postToSfmc(url, accessToken, payload);

        // 6) Interpret and map to SalesforceResponse
        handleSfmcResponse(responseJson, out);

        LOGGER.info("[SFMC] Completed. error={}, httpCode={}, requestId={}",
                out.error, out.httpCode, out.requestId);

        return out;
    }

    // ========================================================================
    // reCAPTCHA
    // ========================================================================

    /**
     * Calculates reCAPTCHA score for this SFMC submission.
     * This method NEVER blocks the submission – any issue results in score 0.0.
     */
    private double resolveRecaptchaScore(RequestParameterMap params,
                                         HttpServletRequest request) {

        String token = getString(params, "g-recaptcha-response", "");
        if (StringUtils.isBlank(token)) {
            LOGGER.info("[SFMC] No g-recaptcha-response found; reCAPTCHA score = 0.0 (submission continues).");
            return 0.0d;
        }

        String secretKey = resolveRecaptchaSecretFromConfig();
        if (StringUtils.isBlank(secretKey)) {
            LOGGER.warn("[SFMC] reCAPTCHA secret key not available; score = 0.0 (submission continues).");
            return 0.0d;
        }

        try {
            double score = Recaptcha.isCaptchaValid(secretKey, token, request);
            LOGGER.info("[SFMC] reCAPTCHA validation completed. score={}", score);
            return score;
        } catch (Exception e) {
            LOGGER.error("[SFMC] reCAPTCHA validation error; score = 0.0 (submission continues).", e);
            return 0.0d;
        }
    }

    /**
     * Reads the reCAPTCHA secret key from another existing OSGi config.
     * Adjust RECAPTCHA_CONFIG_PID and RECAPTCHA_SECRET_PROP to match your setup.
     */
    private String resolveRecaptchaSecretFromConfig() {
        if (configurationAdmin == null) {
            LOGGER.warn("[SFMC] ConfigurationAdmin is not available, cannot read reCAPTCHA secret");
            return "";
        }
        try {
            Configuration cfg = configurationAdmin.getConfiguration(RECAPTCHA_CONFIG_PID, null);
            if (cfg == null) {
                LOGGER.warn("[SFMC] No configuration found for PID={}", RECAPTCHA_CONFIG_PID);
                return "";
            }
            Dictionary<String, Object> props = cfg.getProperties();
            if (props == null) {
                LOGGER.warn("[SFMC] Configuration for PID={} has no properties", RECAPTCHA_CONFIG_PID);
                return "";
            }
            Object v = props.get(RECAPTCHA_SECRET_PROP);
            if (v != null) {
                String secret = v.toString();
                LOGGER.debug("[SFMC] Loaded reCAPTCHA secret from PID={} property={}", RECAPTCHA_CONFIG_PID, RECAPTCHA_SECRET_PROP);
                return secret;
            }
            LOGGER.warn("[SFMC] Property {} not found in PID={}", RECAPTCHA_SECRET_PROP, RECAPTCHA_CONFIG_PID);
        } catch (Exception e) {
            LOGGER.warn("[SFMC] Unable to read reCAPTCHA secret from PID={}", RECAPTCHA_CONFIG_PID, e);
        }
        return "";
    }

    // ========================================================================
    // Auth + POST to SFMC
    // ========================================================================

    private String getAccessToken() {
        String url = authBase + "/v2/token";

        JsonObject body = new JsonObject();
        body.addProperty("grant_type", "client_credentials");
        body.addProperty("client_id", clientId);
        body.addProperty("client_secret", clientSecret);
        body.addProperty("account_id", accountId);

        JsonObject json = apiClient.makeApiCall("POST", url, body, Collections.<String, String>emptyMap());

        if (json == null) {
            LOGGER.error("[SFMC] Auth failed: null response");
            return null;
        }

        if (json.has("access_token") && json.get("access_token").isJsonPrimitive()) {
            String token = json.get("access_token").getAsString();
            if (debugLogs) {
                LOGGER.debug("[SFMC] Auth success. token length={}", token != null ? token.length() : 0);
            }
            return token;
        }

        int code = json.has("httpCode") && json.get("httpCode").isJsonPrimitive()
                ? json.get("httpCode").getAsInt()
                : -1;

        String msg = json.has("message") && json.get("message").isJsonPrimitive()
                ? json.get("message").getAsString()
                : "Unknown auth error";

        LOGGER.error("[SFMC] Auth failed. httpCode={} message={}", code, msg);
        return null;
    }

    private JsonObject postToSfmc(String url, String token, JsonObject payload) {
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer " + token);
        headers.put("Accept", "application/json");
        return apiClient.makeApiCall("POST", url, payload, headers);
    }

    private void handleSfmcResponse(JsonObject responseJson, SalesforceResponse out) {
        if (responseJson == null) {
            out.message = "Null response from SFMC";
            out.error = true;
            out.httpCode = 500;
            return;
        }

        int httpCode = responseJson.has("httpCode") && responseJson.get("httpCode").isJsonPrimitive()
                ? responseJson.get("httpCode").getAsInt()
                : 200;
        out.httpCode = httpCode;

        if (responseJson.has("requestId") && responseJson.get("requestId").isJsonPrimitive()) {
            out.requestId = responseJson.get("requestId").getAsString();
        }

        boolean respError = httpCode >= 400 ||
                (responseJson.has("error") && responseJson.get("error").isJsonPrimitive()
                        && responseJson.get("error").getAsBoolean());
        out.error = respError;

        // Prefer SFMC resultMessages if present
        if (responseJson.has("resultMessages") && responseJson.get("resultMessages").isJsonArray()) {
            JsonArray msgs = responseJson.getAsJsonArray("resultMessages");
            StringBuilder sb = new StringBuilder();
            for (JsonElement e : msgs) {
                if (e.isJsonPrimitive()) {
                    if (sb.length() > 0) {
                        sb.append(" | ");
                    }
                    sb.append(e.getAsString());
                }
            }
            out.message = sb.length() > 0 ? sb.toString() : (respError ? "SFMC call failed" : "SFMC accepted request");
            return;
        }

        // Fallback to "message" from ApiClient / SFMC
        if (responseJson.has("message") && responseJson.get("message").isJsonPrimitive()) {
            out.message = responseJson.get("message").getAsString();
        } else if (!respError) {
            out.message = "SFMC accepted request";
        } else {
            out.message = "SFMC call failed";
        }
    }

    // ========================================================================
    // Payload helpers
    // ========================================================================

    private JsonObject buildPayload(RequestParameterMap params,
                                    String submissionId,
                                    String formId,
                                    double score) {

        JsonObject item = new JsonObject();

        // Mandatory fields
        item.addProperty("AEMSubmissionID", submissionId);
        item.addProperty("FormID", formId);
        item.addProperty("CaptchaScore", score);
        item.addProperty("Timestamp", Instant.now().toString());

        // MessageBody – either explicit or built from params
        String messageBody = getString(params, "MessageBody", "");
        if (StringUtils.isBlank(messageBody)) {
            messageBody = buildMessageBodyFromParams(params);
        }
        item.addProperty("MessageBody", messageBody);

        // Optional typical fields – adjust names to your DE schema
        item.addProperty("FirstName", getString(params, "firstName", ""));
        item.addProperty("LastName", getString(params, "lastName", ""));
        item.addProperty("Email", getString(params, "email", ""));
        item.addProperty("Phone", getString(params, "phone", ""));
        item.addProperty("PostalCode", getString(params, "postalCode", ""));
        item.addProperty("State", getString(params, "state", ""));
        item.addProperty("Country", getString(params, "country", ""));

        JsonArray items = new JsonArray();
        items.add(item);

        JsonObject root = new JsonObject();
        root.add("items", items);
        return root;
    }

    private String buildMessageBodyFromParams(RequestParameterMap params) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, RequestParameter[]> e : params.entrySet()) {
            String key = e.getKey();
            if (INTERNAL_FIELDS.contains(key)) {
                continue;
            }
            RequestParameter[] values = e.getValue();
            if (values != null && values.length > 0) {
                String v = values[0].getString();
                if (StringUtils.isNotBlank(v)) {
                    if (sb.length() > 0) {
                        sb.append("\n");
                    }
                    sb.append(key).append(": ").append(v);
                }
            }
        }
        return sb.toString();
    }

    private String getString(RequestParameterMap params, String key, String def) {
        if (params == null) {
            return def;
        }
        RequestParameter p = params.getValue(key);
        return p != null ? p.getString() : def;
    }
}

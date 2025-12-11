package com.mnt.axp.common.core.services.impl;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.mnt.axp.common.core.config.SfmcConfig;
import com.mnt.axp.common.core.models.form.Container;
import com.mnt.axp.common.core.models.bootstrapform.BootstrapContainer;
import com.mnt.axp.common.core.models.bootstrapform.BootstrapKVPImpl;
import com.mnt.axp.common.core.services.SfmcService;
import com.mnt.axp.common.core.utils.ApiClient;
import com.mnt.axp.common.core.utils.FormHelper;
import com.mnt.axp.common.core.utils.Recaptcha;

import org.apache.commons.lang3.StringUtils;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.request.RequestParameter;
import org.apache.sling.api.request.RequestParameterMap;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
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

/**
 * SFMC integration service.
 *
 * This class:
 *  1) Validates reCAPTCHA using existing Recaptcha helper.
 *  2) Fetches an OAuth access token from SFMC.
 *  3) Resolves the target Data Extension key.
 *  4) Builds a JSON payload from:
 *      - All request parameters (dynamic – supports new fields automatically)
 *      - Hidden / private fields authored on the form (legacy + bootstrap)
 *  5) Posts the payload to SFMC.
 *  6) Maps the response into {@link SalesforceResponse}.
 */
@Component(service = SfmcService.class, immediate = true)
@Designate(ocd = SfmcServiceImpl.SfmcConfig.class)
public class SfmcServiceImpl implements SfmcService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SfmcServiceImpl.class);

    /**
     * Legacy & Bootstrap container resource types.
     * Used to distinguish which Sling Model to adapt to.
     */
    private static final String RT_LEGACY_CONTAINER =
            "axp-common/components/forms/form-container";
    private static final String RT_BOOTSTRAP_CONTAINER =
            "axp-common/components/bootstrap/form/form-container";

    /**
     * Search paths for locating a form based on formPathHash.
     * Tweak if your forms live somewhere more specific.
     */
    private static final List<String> FORM_SEARCH_PATHS =
            Collections.unmodifiableList(Arrays.asList("/content"));

    /**
     * Parameters that should never be forwarded to SFMC.
     */
    private static final Set<String> PARAMS_TO_IGNORE = new HashSet<>(
            Arrays.asList(
                    "g-recaptcha-response",
                    "formPath",
                    "formPathHash",
                    "formResourceType"
            )
    );

    // ------------------------------------------------------------------------
    // OSGi config
    // ------------------------------------------------------------------------

    @ObjectClassDefinition(name = "AXP SFMC Integration")
    public @interface SfmcConfig {

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

        @AttributeDefinition(name = "Recaptcha Public Key")
        String recaptchaPublicKey();

        @AttributeDefinition(name = "Recaptcha Private Key")
        String recaptchaPrivateKey();
    }

    private String authBase;
    private String restBase;
    private String clientId;
    private String clientSecret;
    private String accountId;
    private String defaultDeKey;
    private boolean debugLogs;
    private String recaptchaPublicKey;
    private String recaptchaPrivateKey;

    // Utilities
    private final ApiClient apiClient = new ApiClient();

    @Reference
    private ConfigurationAdmin configurationAdmin;

    @Activate
    protected void activate(final SfmcConfig config) {
        this.authBase = trimTrailingSlash(config.sfmc_auth_base());
        this.restBase = trimTrailingSlash(config.sfmc_rest_base());
        this.clientId = config.sfmc_client_id();
        this.clientSecret = config.sfmc_client_secret();
        this.accountId = config.sfmc_account_id();
        this.defaultDeKey = config.sfmc_default_de_key();
        this.debugLogs = config.debug_logs();
        this.recaptchaPublicKey = config.recaptchaPublicKey();
        this.recaptchaPrivateKey = config.recaptchaPrivateKey();

        LOGGER.debug(
                "[SFMC] Service activated. authBase={}, restBase={}, defaultDeKey={}, debugLogs={}, recaptchaPublicKey set? {}, recaptchaPrivateKey set? {}",
                authBase, restBase, defaultDeKey, debugLogs,
                StringUtils.isNotBlank(recaptchaPublicKey),
                StringUtils.isNotBlank(recaptchaPrivateKey)
        );
    }

    private String trimTrailingSlash(final String value) {
        if (value == null) {
            return null;
        }
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    // ------------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------------

    @Override
    public SalesforceResponse submitToSfmc(final RequestParameterMap params,
                                           final HttpServletRequest request) throws IOException {

        final SalesforceResponse out = new SalesforceResponse();
        final String submissionId = UUID.randomUUID().toString();
        final String formId = getString(params, "formID", "FormID-Unknown");

        LOGGER.debug("[SFMC] New submission. submissionId={}, formId={}", submissionId, formId);

        // 1) reCAPTCHA
        final double score = resolveRecaptchaScore(params, request);
        LOGGER.debug("[SFMC] reCAPTCHA score (will be sent to SFMC): {}", score);

        // 2) OAuth token
        final String accessToken = getAccessToken();
        if (StringUtils.isBlank(accessToken)) {
            out.error = true;
            out.httpCode = 500;
            out.message = "Auth failed: unable to obtain SFMC access token";
            LOGGER.error("[SFMC] {}", out.message);
            return out;
        }
        LOGGER.debug("[SFMC] Obtained SFMC access token (length={})",
                accessToken.length());

        // 3) Data Extension key
        final String deKey = getString(params, "data-extension-key", defaultDeKey);
        if (StringUtils.isBlank(deKey)) {
            out.error = true;
            out.httpCode = 400;
            out.message = "Missing data-extension-key and no default is configured";
            LOGGER.error("[SFMC] {}", out.message);
            return out;
        }
        LOGGER.debug("[SFMC] Using Data Extension key: {}", deKey);

        // 3b) Resolve private/hidden fields from the form models (legacy + bootstrap)
        final Map<String, String> formAuthoredFields = resolveFormAuthoredFields(params, request);
        LOGGER.debug("[SFMC] Resolved {} authored private/hidden fields: {}",
                formAuthoredFields.size(), formAuthoredFields.keySet());

        // 4) Build payload
        final JsonObject payload = buildPayload(params, submissionId, formId, score, formAuthoredFields);
        if (debugLogs) {
            LOGGER.debug("[SFMC] Payload for DE {}: {}", deKey, payload);
        }

        // 5) POST to SFMC
        final String url = restBase + "/data/v1/async/dataextensions/key/" + deKey + "/rows";
        final JsonObject responseJson = postToSfmc(url, accessToken, payload);

        // 6) Map into SalesforceResponse
        handleSfmcResponse(responseJson, out);

        LOGGER.debug("[SFMC] Completed. error={}, httpCode={}, requestId={}",
                out.error, out.httpCode, out.requestId);

        return out;
    }

    // ------------------------------------------------------------------------
    // Step 1: reCAPTCHA (existing helper)
    // ------------------------------------------------------------------------

    /**
     * Uses existing {@link Recaptcha#isCaptchaValid(String, String, HttpServletRequest)}
     * implementation exactly as before.
     */
    private double resolveRecaptchaScore(final RequestParameterMap params,
                                         final HttpServletRequest request) {

        final String token = getString(params, "g-recaptcha-response", "");

        if (StringUtils.isBlank(token)) {
            LOGGER.info("[SFMC] No reCAPTCHA response found; reCAPTCHA score = 0.0 (submission continues).");
            return 0.0;
        }

        final String secretKey = recaptchaPrivateKey;
        if (StringUtils.isBlank(secretKey)) {
            LOGGER.warn("[SFMC] reCAPTCHA secret key not available; score = 0.0 (submission continues).");
            return 0.0;
        }

        try {
            final double score = Recaptcha.isCaptchaValid(secretKey, token, request);
            LOGGER.debug("[SFMC] reCAPTCHA validation completed. score={}", score);
            return score;
        } catch (Exception e) {
            LOGGER.error("[SFMC] reCAPTCHA validation error; score = 0.0 (submission continues).", e);
            return 0.0;
        }
    }

    // ------------------------------------------------------------------------
    // Step 2: OAuth token
    // ------------------------------------------------------------------------

    private String getAccessToken() {
        final String url = authBase + "/v2/token";

        final JsonObject body = new JsonObject();
        body.addProperty("grant_type", "client_credentials");
        body.addProperty("client_id", clientId);
        body.addProperty("client_secret", clientSecret);
        body.addProperty("account_id", accountId);

        LOGGER.debug("[SFMC] Requesting access token from {}", url);

        final JsonObject json = apiClient.makeApiCall("POST", url, body,
                Collections.<String, String>emptyMap());

        if (json == null) {
            LOGGER.error("[SFMC] Auth failed: null response");
            return null;
        }

        if (debugLogs) {
            LOGGER.debug("[SFMC] Auth response: {}", json);
        }

        if (json.has("access_token") && json.get("access_token").isJsonPrimitive()) {
            final String token = json.get("access_token").getAsString();
            LOGGER.debug("[SFMC] Auth success. token length={}", token == null ? 0 : token.length());
            return token;
        }

        int code = 0;
        String msg = "Unknown auth error";
        if (json.has("httpCode") && json.get("httpCode").isJsonPrimitive()) {
            code = json.get("httpCode").getAsInt();
        }
        if (json.has("message") && json.get("message").isJsonPrimitive()) {
            msg = json.get("message").getAsString();
        }

        LOGGER.error("[SFMC] Auth failed. httpCode={} message={}", code, msg);
        return null;
    }

    // ------------------------------------------------------------------------
    // Step 3b: Resolve hidden + private fields from form models
    // ------------------------------------------------------------------------

    /**
     * Resolves all *authored* fields on the form (hidden + private) for both
     * legacy and bootstrap containers.
     *
     * These values will override or supplement the raw request parameters
     * when the payload is built.
     */
    private Map<String, String> resolveFormAuthoredFields(final RequestParameterMap params,
                                                          final HttpServletRequest request) {

        final Map<String, String> authored = new LinkedHashMap<>();

        if (!(request instanceof SlingHttpServletRequest)) {
            LOGGER.debug("[SFMC] Not a SlingHttpServletRequest; skipping form model resolution.");
            return authored;
        }

        final SlingHttpServletRequest slingRequest = (SlingHttpServletRequest) request;
        final ResourceResolver resolver = slingRequest.getResourceResolver();

        Resource formResource = findFormResource(params, resolver);
        if (formResource == null) {
            LOGGER.debug("[SFMC] No form resource resolved from request; no authored fields added.");
            return authored;
        }

        LOGGER.debug("[SFMC] Resolved form resource {} (type={}) for authored fields.",
                formResource.getPath(), formResource.getResourceType());

        try {
            // --- Legacy container ---
            if (formResource.isResourceType(RT_LEGACY_CONTAINER)) {
                final Container model = formResource.adaptTo(Container.class);
                if (model != null) {
                    authored.putAll(FormHelper.getPrivateFields(model));
                    authored.putAll(FormHelper.getHiddenFields(model, slingRequest.getRequestParameterMap()));
                }
            }
            // --- Bootstrap container ---
            else if (formResource.isResourceType(RT_BOOTSTRAP_CONTAINER)) {
                final BootstrapContainer model = formResource.adaptTo(BootstrapContainer.class);
                if (model != null) {
                    authored.putAll(extractBootstrapPrivateFields(model));
                    authored.putAll(extractBootstrapHiddenFields(model, slingRequest.getRequestParameterMap()));
                }
            }
            // --- Fallback: try both models regardless of resourceType ---
            else {
                final Container legacyModel = formResource.adaptTo(Container.class);
                if (legacyModel != null) {
                    authored.putAll(FormHelper.getPrivateFields(legacyModel));
                    authored.putAll(FormHelper.getHiddenFields(legacyModel, slingRequest.getRequestParameterMap()));
                }

                final BootstrapContainer bootstrapModel = formResource.adaptTo(BootstrapContainer.class);
                if (bootstrapModel != null) {
                    authored.putAll(extractBootstrapPrivateFields(bootstrapModel));
                    authored.putAll(extractBootstrapHiddenFields(bootstrapModel, slingRequest.getRequestParameterMap()));
                }
            }
        } catch (Exception e) {
            LOGGER.error("[SFMC] Error resolving authored fields from form at " + formResource.getPath(), e);
        }

        LOGGER.debug("[SFMC] Final authored fields map size={} keys={}",
                authored.size(), authored.keySet());

        return authored;
    }

    /**
     * Attempts to locate the form resource, first by explicit formPath, then
     * by formPathHash + FormHelper.
     */
    private Resource findFormResource(final RequestParameterMap params,
                                      final ResourceResolver resolver) {

        final String explicitPath = getString(params, "formPath", "");
        if (StringUtils.isNotBlank(explicitPath)) {
            final Resource r = resolver.getResource(explicitPath);
            if (r != null) {
                LOGGER.debug("[SFMC] Form resolved via explicit formPath={}", explicitPath);
                return r;
            }
            LOGGER.warn("[SFMC] formPath={} did not resolve to a resource.", explicitPath);
        }

        final String pathHash = getString(params, "formPathHash", "");
        if (StringUtils.isBlank(pathHash)) {
            LOGGER.debug("[SFMC] No formPathHash provided; cannot search for form.");
            return null;
        }

        LOGGER.debug("[SFMC] Searching for form via formPathHash={} in paths {}", pathHash, FORM_SEARCH_PATHS);

        // First try bootstrap container
        Resource form = FormHelper.findForm(pathHash, FORM_SEARCH_PATHS, RT_BOOTSTRAP_CONTAINER, resolver);
        if (form != null) {
            LOGGER.debug("[SFMC] Found bootstrap form resource {}", form.getPath());
            return form;
        }

        // Fallback: legacy container
        form = FormHelper.findForm(pathHash, FORM_SEARCH_PATHS, RT_LEGACY_CONTAINER, resolver);
        if (form != null) {
            LOGGER.debug("[SFMC] Found legacy form resource {}", form.getPath());
            return form;
        }

        LOGGER.warn("[SFMC] No form resource found for formPathHash={}", pathHash);
        return null;
    }

    private Map<String, String> extractBootstrapPrivateFields(final BootstrapContainer model) {
        final Map<String, String> out = new LinkedHashMap<>();
        if (model.getPrivateFields() != null) {
            for (final BootstrapKVPImpl kvp : model.getPrivateFields()) {
                if (kvp != null && StringUtils.isNotBlank(kvp.getKey())) {
                    out.put(kvp.getKey(), StringUtils.defaultString(kvp.getValue()));
                }
            }
        }
        return out;
    }

    private Map<String, String> extractBootstrapHiddenFields(final BootstrapContainer model,
                                                             final RequestParameterMap params) {
        final Map<String, String> out = new LinkedHashMap<>();
        if (model.getHiddenFields() != null) {
            for (final BootstrapKVPImpl kvp : model.getHiddenFields()) {
                if (kvp == null || StringUtils.isBlank(kvp.getKey())) {
                    continue;
                }
                final RequestParameter hiddenParam = params.getValue(kvp.getKey());
                final String value = hiddenParam == null ? "" : hiddenParam.getString();
                out.put(kvp.getKey(), value);
            }
        }
        return out;
    }

    // ------------------------------------------------------------------------
    // Step 4: Build payload
    // ------------------------------------------------------------------------

    private JsonObject buildPayload(final RequestParameterMap params,
                                    final String submissionId,
                                    final String formId,
                                    final double score,
                                    final Map<String, String> authoredFields) {

        final JsonObject item = new JsonObject();

        // --- Core metadata fields (align names with SFMC DE columns) ---
        item.addProperty("AEMSubmissionID", submissionId);
        item.addProperty("FormID", formId);
        // SFMC Postman example uses FormTS; use that instead of "Timestamp"
        item.addProperty("FormTS", Instant.now().toString());
        item.addProperty("CaptchaScore", score);

        // --- 4a. Forward ALL request parameters (dynamic) ---
        for (Map.Entry<String, RequestParameter[]> entry : params.entrySet()) {
            final String key = entry.getKey();
            if (PARAMS_TO_IGNORE.contains(key)) {
                continue;
            }
            if (item.has(key)) {
                // Core field already set, skip
                continue;
            }

            final RequestParameter[] values = entry.getValue();
            if (values == null || values.length == 0) {
                continue;
            }
            final RequestParameter p = values[0];
            final String v = p == null ? "" : p.getString();
            item.addProperty(key, v);
        }

        // --- 4b. Overlay authored private + hidden fields (server-side config) ---
        for (Map.Entry<String, String> e : authoredFields.entrySet()) {
            final String key = e.getKey();
            final String value = e.getValue();
            if (StringUtils.isBlank(key)) {
                continue;
            }
            // Authored values override everything from the request.
            item.addProperty(key, StringUtils.defaultString(value));
        }

        // --- 4c. Special handling for MessageBody ---
        // If MessageBody is still missing, build a simple body from all params.
        if (!item.has("MessageBody")) {
            final String messageBody = buildMessageBodyFromParams(params);
            item.addProperty("MessageBody", messageBody);
        }

        // --- Wrap into { "items": [ item ] } as SFMC expects ---
        final JsonArray items = new JsonArray();
        items.add(item);

        final JsonObject root = new JsonObject();
        root.add("items", items);

        return root;
    }

    /**
     * Fallback builder for MessageBody: pretty-prints all parameters so new fields
     * automatically show up in SFMC emails/logs even if not explicitly mapped.
     */
    private String buildMessageBodyFromParams(final RequestParameterMap params) {
        final StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, RequestParameter[]> entry : params.entrySet()) {
            final String key = entry.getKey();
            if (PARAMS_TO_IGNORE.contains(key)) {
                continue;
            }
            final RequestParameter[] values = entry.getValue();
            if (values == null || values.length == 0) {
                continue;
            }
            final RequestParameter p = values[0];
            final String value = p == null ? "" : p.getString();

            if (StringUtils.isBlank(value)) {
                continue;
            }

            sb.append(key).append(": ").append(value).append("\r\n");
        }
        return sb.toString();
    }

    private String getString(final RequestParameterMap params,
                             final String key,
                             final String def) {
        if (params == null) {
            return def;
        }
        final RequestParameter p = params.getValue(key);
        return p == null ? def : p.getString();
    }

    // ------------------------------------------------------------------------
    // Step 5: POST to SFMC
    // ------------------------------------------------------------------------

    private JsonObject postToSfmc(final String url,
                                  final String token,
                                  final JsonObject payload) {

        final Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + token);
        headers.put("Accept", "application/json");

        LOGGER.debug("[SFMC] POSTing to {} with Authorization header and payload size {} bytes",
                url, payload.toString().length());

        return apiClient.makeApiCall("POST", url, payload, headers);
    }

    // ------------------------------------------------------------------------
    // Step 6: Map response into SalesforceResponse
    // ------------------------------------------------------------------------

    private void handleSfmcResponse(final JsonObject responseJson,
                                    final SalesforceResponse out) {

        out.message = "null response from SFMC";
        out.httpCode = 500;
        out.error = true;

        if (responseJson == null) {
            LOGGER.error("[SFMC] Null response from SFMC");
            return;
        }

        if (debugLogs) {
            LOGGER.debug("[SFMC] Raw SFMC response: {}", responseJson);
        }

        // httpCode
        if (responseJson.has("httpCode") && responseJson.get("httpCode").isJsonPrimitive()) {
            out.httpCode = responseJson.get("httpCode").getAsInt();
        }

        // requestId
        if (responseJson.has("requestId") && responseJson.get("requestId").isJsonPrimitive()) {
            out.requestId = responseJson.get("requestId").getAsString();
        }

        boolean respError = out.httpCode >= 400;

        // "error" flag if present
        if (responseJson.has("error") && responseJson.get("error").isJsonPrimitive()) {
            respError = responseJson.get("error").getAsBoolean();
        }

        // Collect resultMessages if present
        final StringBuilder sb = new StringBuilder();
        if (responseJson.has("resultMessages") && responseJson.get("resultMessages").isJsonArray()) {
            final JsonArray msgs = responseJson.get("resultMessages").getAsJsonArray();
            for (JsonElement el : msgs) {
                if (el != null && el.isJsonObject()) {
                    final JsonObject m = el.getAsJsonObject();
                    final String type = m.has("resultType") ? m.get("resultType").getAsString() : "";
                    final String code = m.has("resultCode") ? m.get("resultCode").getAsString() : "";
                    final String msg = m.has("message") ? m.get("message").getAsString() : "";
                    sb.append('[').append(type).append('/').append(code).append("] ").append(msg).append('\n');
                }
            }
        }

        if (sb.length() > 0) {
            out.message = sb.toString().trim();
        } else if (responseJson.has("message") && responseJson.get("message").isJsonPrimitive()) {
            out.message = responseJson.get("message").getAsString();
        } else {
            out.message = respError ? "SFMC call failed" : "SFMC accepted request";
        }

        out.error = respError;

        LOGGER.info("[SFMC] SFMC response mapped. httpCode={}, error={}, requestId={}, message={}",
                out.httpCode, out.error, out.requestId, out.message);
    }
}

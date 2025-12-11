package com.mnt.axp.common.core.services.impl;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.mnt.axp.common.core.config.SfmcConfig;
import com.mnt.axp.common.core.models.bootstrap.bootstrapform.BootstrapContainer;
import com.mnt.axp.common.core.models.bootstrap.bootstrapform.BootstrapKVPImpl;
import com.mnt.axp.common.core.models.form.Container;
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
import org.osgi.service.component.annotations.*;
import org.osgi.service.metatype.annotations.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.Instant;
import java.util.*;

/**
 * FINAL SFMC SERVICE IMPLEMENTATION
 * Supports: Legacy + Bootstrap Containers
 * Handles: Hidden Fields, Private Fields, Mandatory Fields, Dynamic Payload
 * Goal: Match EXACT SFMC Postman Payload
 */
@Component(service = SfmcService.class, immediate = true)
@Designate(ocd = SfmcServiceImpl.SfmcConfig.class)
public class SfmcServiceImpl implements SfmcService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SfmcServiceImpl.class);

    private static final String RT_LEGACY_CONTAINER =
            "axp-common/components/form/form-container";

    private static final String RT_BOOTSTRAP_CONTAINER =
            "axp-common/components/bootstrap/form/form-container";

    private static final List<String> FORM_SEARCH_PATHS =
            Collections.unmodifiableList(Arrays.asList("/content"));

    private static final Set<String> PARAMS_TO_IGNORE = new HashSet<>(
            Arrays.asList(
                    "g-recaptcha-response",
                    "componentType",
                    "formPath",
                    "formPathHash"
            )
    );

    // Mandatory Private Fields
    private static final List<String> REQUIRED_PRIVATE_FIELDS = Arrays.asList(
            "SubscriberKey",
            "EmailAddress",
            "CcAddress"
            // Add "BccAddress" if you decide to enforce it
    );

    @ObjectClassDefinition(
            name = "AXP SFMC Integration"
    )
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
    private String recaptchaPrivateKey;

    private final ApiClient apiClient = new ApiClient();

    @Activate
    protected void activate(final SfmcConfig config) {
        this.authBase = strip(config.sfmc_auth_base());
        this.restBase = strip(config.sfmc_rest_base());
        this.clientId = config.sfmc_client_id();
        this.clientSecret = config.sfmc_client_secret();
        this.accountId = config.sfmc_account_id();
        this.defaultDeKey = config.sfmc_default_de_key();
        this.debugLogs = config.debug_logs();
        this.recaptchaPrivateKey = config.recaptchaPrivateKey();

        LOGGER.info("[SFMC] Service Activated: REST={}, AUTH={}, DefaultDE={}",
                restBase, authBase, defaultDeKey);
    }

    private String strip(String s) {
        if (s == null) return null;
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    // --------------------------------------------------------------------
    // MAIN ENTRY
    // --------------------------------------------------------------------

    @Override
    public SalesforceResponse submitToSfmc(RequestParameterMap params,
                                           HttpServletRequest request) throws IOException {

        SalesforceResponse out = new SalesforceResponse();
        String submissionId = UUID.randomUUID().toString();
        String formId = get(params, "formID", "");

        LOGGER.info("[SFMC] New submission: submissionId={}, formId={}", submissionId, formId);

        // 1) reCAPTCHA
        double score = resolveRecaptcha(params, request);

        // 2) Get OAuth token
        String token = getAccessToken();
        if (token == null) {
            out.error = true;
            out.httpCode = 500;
            out.message = "Failed to obtain SFMC OAuth token";
            return out;
        }

        // 3) Extract authored fields
        Map<String, String> dialogFields = resolveFormAuthoredFields(params, request);

        // 4) Validate mandatory private fields
        for (String key : REQUIRED_PRIVATE_FIELDS) {
            if (!dialogFields.containsKey(key) || StringUtils.isBlank(dialogFields.get(key))) {
                out.error = true;
                out.httpCode = 400;
                out.message = "Missing required private field: " + key;
                return out;
            }
        }

        // 5) Build Payload
        JsonObject payload = buildPayload(params, dialogFields, submissionId, formId, score);

        if (debugLogs) {
            LOGGER.debug("[SFMC] Payload: {}", payload);
        }

        // 6) Determine DE key
        String deKey = get(params, "data-extension-key", defaultDeKey);

        // 7) POST to SFMC
        String url = restBase + "/data/v1/async/dataextensions/key/" + deKey + "/rows";
        JsonObject resp = apiClient.makeApiCall("POST", url, payload,
                Collections.singletonMap("Authorization", "Bearer " + token));

        // 8) Map SFMC response
        mapSfmcResponse(resp, out);

        return out;
    }

    // --------------------------------------------------------------------
    // RECAPTCHA
    // --------------------------------------------------------------------

    private double resolveRecaptcha(RequestParameterMap params, HttpServletRequest request) {
        String token = get(params, "g-recaptcha-response", "");
        if (StringUtils.isBlank(token) || StringUtils.isBlank(recaptchaPrivateKey)) {
            return 0.0;
        }
        try {
            return Recaptcha.isCaptchaValid(recaptchaPrivateKey, token, request);
        } catch (Exception e) {
            LOGGER.error("[SFMC] Recaptcha error", e);
            return 0.0;
        }
    }

    // --------------------------------------------------------------------
    // OAUTH TOKEN
    // --------------------------------------------------------------------

    private String getAccessToken() {

        JsonObject body = new JsonObject();
        body.addProperty("grant_type", "client_credentials");
        body.addProperty("client_id", clientId);
        body.addProperty("client_secret", clientSecret);
        body.addProperty("account_id", accountId);

        JsonObject resp = apiClient.makeApiCall("POST", authBase + "/v2/token", body, new HashMap<>());

        if (resp == null || !resp.has("access_token")) {
            LOGGER.error("[SFMC] OAuth failed: {}", resp);
            return null;
        }
        return resp.get("access_token").getAsString();
    }

    // --------------------------------------------------------------------
    // FORM AUTHORING RESOLUTION
    // --------------------------------------------------------------------

    private Map<String, String> resolveFormAuthoredFields(RequestParameterMap params,
                                                          HttpServletRequest request) {

        Map<String, String> out = new LinkedHashMap<>();

        if (!(request instanceof SlingHttpServletRequest)) return out;

        SlingHttpServletRequest slingReq = (SlingHttpServletRequest) request;
        ResourceResolver rr = slingReq.getResourceResolver();

        Resource form = findFormResource(params, rr);
        if (form == null) return out;

        // Legacy
        if (form.isResourceType(RT_LEGACY_CONTAINER)) {
            Container model = form.adaptTo(Container.class);
            if (model != null) {
                out.putAll(FormHelper.getPrivateFields(model));
                out.putAll(FormHelper.getHiddenFields(model, slingReq.getRequestParameterMap()));
            }
        }

        // Bootstrap
        if (form.isResourceType(RT_BOOTSTRAP_CONTAINER)) {
            BootstrapContainer model = form.adaptTo(BootstrapContainer.class);
            if (model != null) {
                out.putAll(extract(model.getPrivateFields()));
                out.putAll(extractHidden(model.getHiddenFields(), slingReq.getRequestParameterMap()));
            }
        }

        return out;
    }

    private Resource findFormResource(RequestParameterMap params, ResourceResolver rr) {

        String explicit = get(params, "formPath", "");
        if (StringUtils.isNotBlank(explicit)) {
            Resource r = rr.getResource(explicit);
            if (r != null) return r;
        }

        String hash = get(params, "formPathHash", "");
        if (StringUtils.isBlank(hash)) return null;

        // Try bootstrap
        Resource r = FormHelper.findForm(hash, FORM_SEARCH_PATHS, RT_BOOTSTRAP_CONTAINER, rr);
        if (r != null) return r;

        // Legacy
        return FormHelper.findForm(hash, FORM_SEARCH_PATHS, RT_LEGACY_CONTAINER, rr);
    }

    private Map<String, String> extract(List<BootstrapKVPImpl> kvps) {
        Map<String, String> out = new LinkedHashMap<>();
        if (kvps != null) {
            kvps.forEach(k -> out.put(k.getKey(), k.getValue()));
        }
        return out;
    }

    private Map<String, String> extractHidden(List<BootstrapKVPImpl> kvps,
                                              RequestParameterMap params) {
        Map<String, String> out = new LinkedHashMap<>();
        if (kvps != null) {
            for (BootstrapKVPImpl kvp : kvps) {
                RequestParameter p = params.getValue(kvp.getKey());
                out.put(kvp.getKey(), p == null ? "" : p.getString());
            }
        }
        return out;
    }

    // --------------------------------------------------------------------
    // PAYLOAD BUILDER
    // --------------------------------------------------------------------

    private JsonObject buildPayload(RequestParameterMap params,
                                    Map<String, String> dialogFields,
                                    String submissionId,
                                    String formId,
                                    double score) {

        JsonObject item = new JsonObject();
        item.addProperty("AEMSubmissionID", submissionId);
        item.addProperty("FormID", formId);
        item.addProperty("Timestamp", Instant.now().toString());
        item.addProperty("CaptchaScore", score);

        // Required private fields (map early)
        item.addProperty("SubscriberKey", dialogFields.get("SubscriberKey"));
        item.addProperty("EmailAddress", dialogFields.get("EmailAddress"));
        item.addProperty("CcAddress", dialogFields.get("CcAddress"));

        if (dialogFields.containsKey("BccAddress")) {
            item.addProperty("BccAddress", dialogFields.get("BccAddress"));
        }

        // Add all request fields
        for (String key : params.keySet()) {
            if (PARAMS_TO_IGNORE.contains(key)) continue;
            if (!item.has(key)) {
                RequestParameter p = params.getValue(key);
                if (p != null) item.addProperty(key, p.getString());
            }
        }

        // Override with authored values
        for (Map.Entry<String, String> e : dialogFields.entrySet()) {
            item.addProperty(e.getKey(), e.getValue());
        }

        // MessageBody fallback
        if (!item.has("MessageBody")) {
            item.addProperty("MessageBody", buildMessageBody(params));
        }

        JsonArray arr = new JsonArray();
        arr.add(item);

        JsonObject payload = new JsonObject();
        payload.add("items", arr);

        return payload;
    }

    private String buildMessageBody(RequestParameterMap params) {
        StringBuilder sb = new StringBuilder();
        for (String key : params.keySet()) {
            if (PARAMS_TO_IGNORE.contains(key)) continue;
            RequestParameter p = params.getValue(key);
            if (p != null && StringUtils.isNotBlank(p.getString())) {
                sb.append(key).append(": ").append(p.getString()).append("\n");
            }
        }
        return sb.toString();
    }

    private String get(RequestParameterMap map, String key, String def) {
        RequestParameter p = map.getValue(key);
        return p == null ? def : p.getString();
    }

    // --------------------------------------------------------------------
    // RESPONSE MAPPING
    // --------------------------------------------------------------------

    private void mapSfmcResponse(JsonObject json, SalesforceResponse out) {

        if (json == null) {
            out.error = true;
            out.message = "Null response from SFMC";
            out.httpCode = 500;
            return;
        }

        out.httpCode = json.has("httpCode") ?
                json.get("httpCode").getAsInt() : 200;

        out.requestId = json.has("requestId") ?
                json.get("requestId").getAsString() : "";

        if (json.has("error")) {
            out.error = json.get("error").getAsBoolean();
        } else {
            out.error = out.httpCode >= 400;
        }

        if (json.has("message")) {
            out.message = json.get("message").getAsString();
        } else {
            out.message = out.error ? "SFMC call failed" : "SFMC accepted request";
        }
    }
}

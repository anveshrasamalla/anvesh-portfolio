package com.mnt.axp.common.core.services.impl;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.mnt.axp.common.core.services.api.SfmcService;
import com.mnt.axp.common.core.utils.ApiClient;
import com.mnt.axp.common.core.utils.Recaptcha;
import org.apache.sling.api.request.RequestParameter;
import org.apache.sling.api.request.RequestParameterMap;
import org.osgi.service.component.annotations.*;
import org.osgi.service.metatype.annotations.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * SFMC submit service.
 * - Reads OSGi config for SFMC bases + client creds.
 * - Optional local proxy toggle (use_proxy) to route via /bin/sfmc/proxy.
 * - Reuses existing ApiClient and Recaptcha utilities.
 * - Mandatory fields ensured: AEMSubmissionID, TimeStamp (can be blank), FormID, MessageBody, CaptchaScore.
 */
@Component(service = SfmcService.class, immediate = true)
@Designate(ocd = SfmcServiceImpl.Config.class)
public class SfmcServiceImpl implements SfmcService {

    private static final Logger LOG = LoggerFactory.getLogger(SfmcServiceImpl.class);

    // ---- config ----
    @ObjectClassDefinition(name = "AXP SFMC Integration (New)")
    public @interface Config {
        @AttributeDefinition(name = "Auth Base URL", description = "e.g., https://<tenant>.auth.marketingcloudapis.com")
        String auth_base();

        @AttributeDefinition(name = "REST Base URL", description = "e.g., https://<tenant>.rest.marketingcloudapis.com")
        String rest_base();

        @AttributeDefinition(name = "Client ID")
        String client_id();

        @AttributeDefinition(name = "Client Secret")
        String client_secret();

        @AttributeDefinition(name = "Account ID")
        String account_id();

        @AttributeDefinition(name = "Use Proxy (/bin/sfmc/proxy)", description = "Local only. When true, routes calls through the proxy servlet.")
        boolean use_proxy() default false;

        @AttributeDefinition(name = "Proxy Base", description = "Usually /bin/sfmc/proxy")
        String proxy_base() default "/bin/sfmc/proxy";
    }

    private String authBase;
    private String restBase;
    private String clientId;
    private String clientSecret;
    private String accountId;
    private boolean useProxy;
    private String proxyBase;

    private final ApiClient apiClient = new ApiClient();

    // internal skip list (kept tiny & readable)
    private static final Set<String> INTERNAL_SKIP = new HashSet<String>(Arrays.asList(
            "g-recaptcha-response",
            ":cq_csrf_token",
            "_charset_"
    ));

    private static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ofPattern("MM/dd/yyyy HH:mm").withZone(ZoneId.systemDefault());

    @Activate @Modified
    protected void activate(Config cfg) {
        authBase     = trim(cfg.auth_base());
        restBase     = trim(cfg.rest_base());
        clientId     = trim(cfg.client_id());
        clientSecret = trim(cfg.client_secret());
        accountId    = trim(cfg.account_id());
        useProxy     = cfg.use_proxy();
        proxyBase    = trim(cfg.proxy_base());

        LOG.info("SFMC service active. useProxy={} proxyBase={}", useProxy, proxyBase);
    }

    private String trim(String s) { return s == null ? "" : s.trim(); }

    // route builder (proxy vs direct)
    private String tokenUrl() {
        return useProxy ? (proxyBase + "?target=auth") : (authBase + "/v2/token");
    }
    private String deUrl(String dePath) {
        return useProxy ? (proxyBase + "?target=rest&path=" + dePath) : (restBase + dePath);
    }

    @Override
    public SalesforceResponse submitToSfmc(RequestParameterMap params, HttpServletRequest request) throws IOException {
        SalesforceResponse out = new SalesforceResponse();

        // 1) reCAPTCHA score
        double score = getCaptchaScore(params, request);
        out.score = score;
        LOG.debug("reCAPTCHA score={}", score);

        // 2) Build payload (minimal, readable)
        String submissionId = UUID.randomUUID().toString();
        JsonObject payload = buildPayload(params, submissionId, score);

        // 3) Auth
        String token = getToken();
        if (token == null) {
            out.message  = "Auth failed: Invalid token response";
            out.error    = true;
            out.httpCode = 500;
            return out;
        }

        // 4) Pick DE path (front-end passes 'de_key'; fallback to a sensible default)
        String deKey = getParam(params, "de_key", "AEM-FORM-ENDPNT-INTRNL-TEST");
        final String dePath = "/data/v1/async/dataextensions/key:" + deKey + "/rows";

        // 5) Submit
        PostOutcome po = postToDE(token, dePath, payload);
        out.message   = po.message;
        out.error     = po.error;
        out.httpCode  = po.httpCode;
        out.requestId = po.requestId;

        return out;
    }

    // ---------- helpers ----------

    private double getCaptchaScore(RequestParameterMap p, HttpServletRequest req) {
        try {
            RequestParameter rp = p.getValue("g-recaptcha-response");
            String token = (rp != null) ? rp.getString() : "";
            if (token == null || token.trim().isEmpty()) return 0.0;

            // Use your existing Recaptcha utility (secret key is configured there / or global)
            // We don't need 'publicKey' for verification, pass empty.
            return Recaptcha.isCaptchaValid("dummy-secret-not-used-here", "", token, req);
        } catch (Exception e) {
            LOG.warn("reCAPTCHA error", e);
            return 0.0;
        }
    }

    private JsonObject buildPayload(RequestParameterMap p, String submissionId, double score) {
        JsonObject item = new JsonObject();

        // Copy string params, skip internals
        for (Map.Entry<String, RequestParameter[]> e : p.entrySet()) {
            String k = e.getKey();
            if (INTERNAL_SKIP.contains(k)) continue;
            RequestParameter[] rps = e.getValue();
            if (rps != null && rps.length > 0) {
                String v = rps[0].getString();
                item.addProperty(k, v);
            }
        }

        // Mandatory / ensured fields
        if (!item.has("AEMSubmissionID")) item.addProperty("AEMSubmissionID", submissionId);
        if (!item.has("TimeStamp"))       item.addProperty("TimeStamp", TS_FMT.format(java.time.Instant.now()));
        if (!item.has("FormID"))          item.addProperty("FormID", getParam(p, "FormID", ""));
        if (!item.has("MessageBody"))     item.addProperty("MessageBody", getParam(p, "MessageBody", ""));
        item.addProperty("CaptchaScore", String.valueOf(score));

        // Wrap under items[]
        JsonArray items = new JsonArray();
        items.add(item);
        JsonObject payload = new JsonObject();
        payload.add("items", items);

        LOG.debug("Payload: {}", payload);
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

        JsonObject j = apiClient.makeApiCall("POST", tokenUrl(), req, java.util.Collections.<String,String>emptyMap());
        if (j == null || !j.has("access_token")) {
            LOG.error("Auth failed: {}", (j == null ? "null response" : j.toString()));
            return null;
        }
        String tok = j.get("access_token").getAsString();
        LOG.debug("Got access_token ({} chars)", tok == null ? 0 : tok.length());
        return tok;
    }

    private PostOutcome postToDE(String accessToken, String dePath, JsonObject payload) {
        Map<String,String> headers = new HashMap<String,String>();
        headers.put("Authorization", "Bearer " + accessToken);

        JsonObject j = apiClient.makeApiCall("POST", deUrl(dePath), payload, headers);

        PostOutcome out = new PostOutcome();
        // Normalize based on SFMC async insert (202 + {requestId, resultMessages:[]})
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

    // small internal DTO
    private static class PostOutcome {
        String  requestId;
        String  message;
        boolean error;
        int     httpCode;
    }
}

package com.mnt.axp.common.core.utils;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.apache.jackrabbit.webdav.DavConstants.HEADER_CONTENT_TYPE;

/**
 * ApiClient with optional, DEV-ONLY "trust-all" TLS to bypass PKIX locally.
 *
 * NORMAL BEHAVIOR (default):
 *   - Uses JVM/AEM truststore; validates server certs and hostnames.
 *
 * DEV-ONLY OVERRIDE:
 *   - Start AEM with: -Daxp.ssl.trustAll=true
 *   - Then, for HTTPS connections opened by THIS client, we install an
 *     in-memory TrustManager that accepts all cert chains and a hostname verifier
 *     that always returns true. This resolves PKIX in local sandboxes.
 *
 * IMPORTANT:
 *   - Do NOT enable in QA/Stage/Prod. Use proper certs or Granite SSL truststore.
 *   - The switch is per-JVM via system property, so it is easy to remove.
 */
public class ApiClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiClient.class);

    // timeouts
    private static final int CONNECTION_TIMEOUT = 5000;
    private static final int SOCKET_TIMEOUT = 5000;

    // DEV flag (read once, kept simple & explicit)
    private static final String PROP_TRUST_ALL = "axp.ssl.trustAll";
    private static final boolean TRUST_ALL_ENABLED = Boolean.getBoolean(PROP_TRUST_ALL);

    // Lazy singletons for the DEV trust-all context
    private static volatile SSLSocketFactory TRUST_ALL_FACTORY;
    private static final HostnameVerifier TRUST_ALL_HOSTNAMES = new HostnameVerifier() {
        @Override public boolean verify(String hostname, SSLSession session) { return true; }
    };

    public ApiClient() {}

    public JsonObject makeApiCall(String method, String apiUrl, JsonObject requestData, Map<String, String> requestHeaders) {
        HttpURLConnection conn = null;
        try {
            // 1) Defensive cleanup for POST JSON (remove empty-string primitives)
            if ("POST".equalsIgnoreCase(method) && requestData != null) {
                final List<String> remove = new ArrayList<String>();
                for (String k : requestData.keySet()) {
                    try {
                        if (requestData.get(k).getAsString().isEmpty()) remove.add(k);
                    } catch (IllegalStateException ignore) { /* non-string value is fine */ }
                }
                for (String k : remove) requestData.remove(k);
            }

            // 2) Open connection (ensure TLS tweaks are applied if dev flag is on)
            URL url = new URL(apiUrl);
            conn = open(url); // <= minimal change: central place to attach trust-all if enabled

            conn.setConnectTimeout(CONNECTION_TIMEOUT);
            conn.setReadTimeout(SOCKET_TIMEOUT);
            conn.setRequestMethod(method);
            conn.setRequestProperty(HEADER_CONTENT_TYPE, "application/json; charset=UTF-8");
            conn.setDoOutput(true);

            // 3) Write headers/body for POST
            if ("POST".equalsIgnoreCase(method)) {
                if (requestHeaders != null) {
                    for (Map.Entry<String,String> e : requestHeaders.entrySet()) {
                        conn.setRequestProperty(e.getKey(), e.getValue());
                    }
                }
                if (requestData != null) {
                    OutputStream os = conn.getOutputStream();
                    try {
                        os.write(requestData.toString().getBytes(StandardCharsets.UTF_8));
                    } finally {
                        os.close();
                    }
                }
            }

            // 4) Read response
            final int code = conn.getResponseCode();
            if (code == HttpURLConnection.HTTP_OK || code == HttpURLConnection.HTTP_ACCEPTED) {
                BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
                StringBuilder sb = new StringBuilder();
                try {
                    String line;
                    while ((line = rd.readLine()) != null) sb.append(line);
                } finally {
                    rd.close();
                }
                return new Gson().fromJson(sb.toString(), JsonObject.class);
            } else {
                // Try to capture error body to help debugging PKIX or 401/403/etc.
                String msg = conn.getResponseMessage();
                try {
                    if (conn.getErrorStream() != null) {
                        BufferedReader er = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8));
                        StringBuilder eb = new StringBuilder();
                        String ln; while ((ln = er.readLine()) != null) eb.append(ln);
                        er.close();
                        if (eb.length() > 0) msg = msg + " | body=" + eb.toString();
                    }
                } catch (Exception ignore) {}
                LOGGER.warn("ApiClient: non-OK response {} from {}", code, apiUrl);
                return ErrorResponseFactory.createErrorResponse(
                        "API call failed with response code: " + code + ". Error message: " + msg);
            }

        } catch (SSLHandshakeException she) {
            // Classic PKIX failure surface
            LOGGER.error("TLS handshake failed: {}", she.getMessage());
            if (!TRUST_ALL_ENABLED) {
                LOGGER.error("Hint: enable DEV-only trust-all with -D{}=true (local only) or import the server cert chain into JVM/Granite truststore.", PROP_TRUST_ALL);
            }
            return ErrorResponseFactory.createErrorResponse("TLS handshake failed: " + she.getMessage());

        } catch (IOException e) {
            LOGGER.error("ApiClient IOException calling {}", apiUrl, e);
            return ErrorResponseFactory.createErrorResponse("API call failed with an IOException: " + e.getMessage());

        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /**
     * Open URLConnection. If https:// and DEV flag is ON, attach a trust-all
     * SSLSocketFactory and all-hostnames verifier to THIS connection only.
     * This keeps blast-radius low and is easy to remove later.
     */
    private HttpURLConnection open(URL url) throws IOException {
        URLConnection raw = url.openConnection();
        if (!"https".equalsIgnoreCase(url.getProtocol())) {
            return (HttpURLConnection) raw;
        }

        HttpsURLConnection https = (HttpsURLConnection) raw;

        if (TRUST_ALL_ENABLED) {
            try {
                if (TRUST_ALL_FACTORY == null) {
                    synchronized (ApiClient.class) {
                        if (TRUST_ALL_FACTORY == null) TRUST_ALL_FACTORY = buildTrustAllFactory();
                    }
                }
                https.setSSLSocketFactory(TRUST_ALL_FACTORY);
                https.setHostnameVerifier(TRUST_ALL_HOSTNAMES);
                LOGGER.warn("ApiClient: DEV trust-all TLS is active for {}", url.getHost());
            } catch (GeneralSecurityException gse) {
                LOGGER.error("ApiClient: failed to init DEV trust-all TLS", gse);
            }
        }

        return https;
    }

    /** Build an in-memory trust-all socket factory (DEV ONLY). */
    private static SSLSocketFactory buildTrustAllFactory() throws GeneralSecurityException {
        TrustManager[] trustAll = new TrustManager[] {
            new X509TrustManager() {
                @Override public void checkClientTrusted(X509Certificate[] chain, String authType) { }
                @Override public void checkServerTrusted(X509Certificate[] chain, String authType) { }
                @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, new SecureRandom());
        return ctx.getSocketFactory();
    }
}

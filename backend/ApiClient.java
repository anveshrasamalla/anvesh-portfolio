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
 * ApiClient with optional "trust-all SSL" for DEV to bypass PKIX errors.
 * Enable by starting AEM with:  -Daxp.ssl.trustAll=true
 *
 * NEVER enable trustAll in QA/Stage/Prod. Use a proper truststore there.
 */
public class ApiClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiClient.class);

    private static final int CONNECTION_TIMEOUT = 5000;
    private static final int SOCKET_TIMEOUT = 5000;

    // System property toggles
    private static final String PROP_TRUST_ALL = "axp.ssl.trustAll";
    private static final String PROP_SSL_DEBUG = "axp.ssl.debug"; // optional: -Daxp.ssl.debug=true

    // Cached trust-all objects (created lazily)
    private static volatile SSLSocketFactory TRUST_ALL_FACTORY;
    private static final HostnameVerifier TRUST_ALL_HOSTNAMES = new HostnameVerifier() {
        @Override public boolean verify(String hostname, SSLSession session) {
            // DEV-ONLY: allow all hostnames.
            // If you want to be slightly stricter, replace with:
            // return hostname != null && hostname.endsWith(".marketingcloudapis.com");
            return true;
        }
    };

    public ApiClient() {}

    public JsonObject makeApiCall(String method, String apiUrl, JsonObject requestData, Map<String, String> requestHeaders) {
        HttpURLConnection conn = null;
        try {
            // prune empty string values on POST
            if ("POST".equalsIgnoreCase(method) && requestData != null) {
                List<String> remove = new ArrayList<String>();
                for (String k : requestData.keySet()) {
                    try {
                        if (requestData.get(k).getAsString().isEmpty()) remove.add(k);
                    } catch (IllegalStateException ignore) { /* non-string node */ }
                }
                for (String k : remove) requestData.remove(k);
            }

            URL url = new URL(apiUrl);
            conn = open(url);
            conn.setConnectTimeout(CONNECTION_TIMEOUT);
            conn.setReadTimeout(SOCKET_TIMEOUT);
            conn.setRequestMethod(method);
            conn.setRequestProperty(HEADER_CONTENT_TYPE, "application/json; charset=UTF-8");
            conn.setDoOutput(true);

            if ("POST".equalsIgnoreCase(method)) {
                if (requestHeaders != null) {
                    for (Map.Entry<String,String> e : requestHeaders.entrySet()) {
                        conn.setRequestProperty(e.getKey(), e.getValue());
                    }
                }
                if (requestData != null) {
                    OutputStream os = conn.getOutputStream();
                    try { os.write(requestData.toString().getBytes(StandardCharsets.UTF_8)); }
                    finally { os.close(); }
                }
            }

            int code = conn.getResponseCode();
            if (code == HttpURLConnection.HTTP_OK || code == 202) {
                BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
                StringBuilder sb = new StringBuilder();
                try { String line; while ((line = rd.readLine()) != null) sb.append(line); }
                finally { rd.close(); }
                return new Gson().fromJson(sb.toString(), JsonObject.class);
            } else {
                // Try to read error stream for details
                String msg = conn.getResponseMessage();
                try {
                    if (conn.getErrorStream() != null) {
                        BufferedReader er = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8));
                        StringBuilder eb = new StringBuilder();
                        String ln;
                        while ((ln = er.readLine()) != null) eb.append(ln);
                        er.close();
                        if (eb.length() > 0) msg = msg + " | body=" + eb.toString();
                    }
                } catch (Exception ignore) {}
                return ErrorResponseFactory.createErrorResponse(
                        "API call failed with response code: " + code + ". Error message: " + msg);
            }
        } catch (SSLHandshakeException she) {
            // Common when PKIX fails
            logSslHint(she);
            return ErrorResponseFactory.createErrorResponse("TLS handshake failed: " + she.getMessage());
        } catch (IOException e) {
            return ErrorResponseFactory.createErrorResponse("API call failed with an IOException: " + e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /**
     * Opens a URL connection. If HTTPS and the system property axp.ssl.trustAll=true is set,
     * applies a "trust-all" SSLSocketFactory + HostnameVerifier for THIS CONNECTION ONLY.
     */
    private HttpURLConnection open(URL url) throws IOException {
        URLConnection raw = url.openConnection();

        if ("https".equalsIgnoreCase(url.getProtocol())) {
            HttpsURLConnection https = (HttpsURLConnection) raw;

            if (Boolean.getBoolean(PROP_TRUST_ALL)) {
                try {
                    if (TRUST_ALL_FACTORY == null) {
                        synchronized (ApiClient.class) {
                            if (TRUST_ALL_FACTORY == null) {
                                TRUST_ALL_FACTORY = buildTrustAllFactory();
                                LOGGER.warn("ApiClient: TRUST-ALL SSL ENABLED ({}=true). DEV ONLY. Do NOT use in prod.",
                                        PROP_TRUST_ALL);
                            }
                        }
                    }
                    https.setSSLSocketFactory(TRUST_ALL_FACTORY);
                    https.setHostnameVerifier(TRUST_ALL_HOSTNAMES);

                    if (Boolean.getBoolean(PROP_SSL_DEBUG)) {
                        System.setProperty("javax.net.debug", "ssl,handshake");
                    }
                } catch (GeneralSecurityException gse) {
                    LOGGER.error("Failed to initialize trust-all SSL context", gse);
                    // fall back to default SSL (will still throw PKIX if not trusted)
                }
            }
            return https;
        }
        return (HttpURLConnection) raw;
    }

    /** Build a trust-all SSLSocketFactory (DEV ONLY). */
    private static SSLSocketFactory buildTrustAllFactory() throws GeneralSecurityException {
        TrustManager[] trustAll = new TrustManager[] {
            new X509TrustManager() {
                @Override public void checkClientTrusted(X509Certificate[] chain, String authType) { /* no-op */ }
                @Override public void checkServerTrusted(X509Certificate[] chain, String authType) { /* no-op */ }
                @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, new SecureRandom());
        return ctx.getSocketFactory();
    }

    private void logSslHint(Exception e) {
        LOGGER.error("TLS handshake error (likely PKIX). {}", e.getMessage());
        LOGGER.error("Hints:");
        LOGGER.error(" - Import SFMC cert chain into your JVM truststore or Granite SSL Service.");
        LOGGER.error(" - Or start AEM with -D{}=true (DEV ONLY) to bypass verification in ApiClient.", PROP_TRUST_ALL);
        LOGGER.error(" - To debug, add -D{}=true", PROP_SSL_DEBUG);
    }
}

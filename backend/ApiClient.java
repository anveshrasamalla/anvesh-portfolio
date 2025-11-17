package com.mnt.axp.common.core.utils;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.apache.jackrabbit.webdav.DavConstants.HEADER_CONTENT_TYPE;

/**
 * Simple JSON HTTP client used by SFMC integration.
 *
 * - Removes empty string fields from JSON payloads.
 * - Always returns a JsonObject (never throws on non-JSON).
 * - On errors, returns: { error:true, message, httpCode, bodyPreview? }.
 */
public class ApiClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiClient.class);

    private static final int CONNECTION_TIMEOUT = 10000;
    private static final int READ_TIMEOUT = 10000;

    private static final Gson GSON = new Gson();

    public JsonObject makeApiCall(String method,
                                  String apiUrl,
                                  JsonObject requestData,
                                  Map<String, String> requestHeaders) {

        HttpURLConnection conn = null;
        try {
            // Clean payload for POST
            if ("POST".equalsIgnoreCase(method) && requestData != null) {
                List<String> remove = new ArrayList<String>();
                for (String key : requestData.keySet()) {
                    try {
                        if (requestData.get(key).isJsonNull()
                                || requestData.get(key).getAsString().isEmpty()) {
                            remove.add(key);
                        }
                    } catch (IllegalStateException ignore) {
                        // non-string node, keep it
                    }
                }
                for (String key : remove) {
                    requestData.remove(key);
                }
            }

            LOGGER.debug("[ApiClient] {} {}", method, apiUrl);
            if (requestData != null) {
                LOGGER.debug("[ApiClient] payload={}", requestData.toString());
            }

            URL url = new URL(apiUrl);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(CONNECTION_TIMEOUT);
            conn.setReadTimeout(READ_TIMEOUT);
            conn.setRequestMethod(method);
            conn.setDoOutput("POST".equalsIgnoreCase(method));
            conn.setRequestProperty(HEADER_CONTENT_TYPE, "application/json; charset=UTF-8");

            if (requestHeaders != null) {
                for (Map.Entry<String, String> e : requestHeaders.entrySet()) {
                    conn.setRequestProperty(e.getKey(), e.getValue());
                }
            }

            if ("POST".equalsIgnoreCase(method) && requestData != null) {
                OutputStream os = conn.getOutputStream();
                try {
                    os.write(requestData.toString().getBytes(StandardCharsets.UTF_8));
                } finally {
                    os.close();
                }
            }

            int code = conn.getResponseCode();
            String body = readBody(code < 400 ? conn.getInputStream() : conn.getErrorStream());
            LOGGER.debug("[ApiClient] response code={} body={}", code, body);

            if (body == null || body.trim().isEmpty()) {
                JsonObject out = new JsonObject();
                out.addProperty("httpCode", code);
                return out;
            }

            try {
                JsonObject json = GSON.fromJson(body, JsonObject.class);
                if (!json.has("httpCode")) {
                    json.addProperty("httpCode", code);
                }
                return json;
            } catch (JsonSyntaxException ex) {
                JsonObject err = new JsonObject();
                err.addProperty("message", "Non-JSON response");
                err.addProperty("httpCode", code);
                String preview = body.length() > 512 ? body.substring(0, 512) : body;
                err.addProperty("bodyPreview", preview);
                err.addProperty("error", true);
                return err;
            }
        } catch (IOException e) {
            LOGGER.error("[ApiClient] {} {} failed with IOException", method, apiUrl, e);
            JsonObject err = new JsonObject();
            err.addProperty("message", "API call failed with IOException: " + e.getMessage());
            err.addProperty("httpCode", 500);
            err.addProperty("error", true);
            return err;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private String readBody(InputStream in) throws IOException {
        if (in == null) {
            return null;
        }
        BufferedReader rd = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        try {
            String line;
            while ((line = rd.readLine()) != null) {
                sb.append(line);
            }
        } finally {
            rd.close();
        }
        return sb.toString();
    }
}

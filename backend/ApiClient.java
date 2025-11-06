package com.mnt.axp.common.core.utils;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.apache.jackrabbit.webdav.DavConstants.HEADER_CONTENT_TYPE;

public class ApiClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiClient.class);
    private static final int CONNECTION_TIMEOUT = 5000;
    private static final int SOCKET_TIMEOUT = 5000;

    public JsonObject makeApiCall(String method, String apiUrl, JsonObject requestData, Map<String, String> requestHeaders) {
        HttpURLConnection conn = null;
        try {
            if ("POST".equalsIgnoreCase(method) && requestData != null) {
                List<String> remove = new ArrayList<String>();
                for (String k : requestData.keySet()) {
                    try { if (requestData.get(k).getAsString().isEmpty()) remove.add(k); }
                    catch (IllegalStateException ignore) {}
                }
                for (String k : remove) requestData.remove(k);
            }

            URL url = new URL(apiUrl);
            conn = (HttpURLConnection) url.openConnection();
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
            if (code == 200 || code == 202) {
                BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
                StringBuilder sb = new StringBuilder();
                try { String line; while ((line = rd.readLine()) != null) sb.append(line); }
                finally { rd.close(); }
                return new Gson().fromJson(sb.toString(), JsonObject.class);
            } else {
                return ErrorResponseFactory.createErrorResponse(
                        "API call failed with response code: " + code + ". Error message: " + conn.getResponseMessage());
            }
        } catch (IOException e) {
            return ErrorResponseFactory.createErrorResponse("API call failed with an IOException: " + e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
    }
}

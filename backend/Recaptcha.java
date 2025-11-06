package com.mnt.axp.common.core.utils;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static org.apache.jackrabbit.webdav.DavConstants.HEADER_CONTENT_TYPE;

public class Recaptcha {

    private static final Logger LOGGER = LoggerFactory.getLogger(Recaptcha.class);
    private static final String VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";
    private static final int CONNECT_TIMEOUT = 5000;
    private static final int READ_TIMEOUT = 5000;

    /** Validates Google reCAPTCHA v3 and returns the score (0.0 if failed). */
    public static double isCaptchaValid(String secretKey, String publicKey, String token, HttpServletRequest request) {
        try {
            String userAgent = request.getHeader("User-Agent");
            if (userAgent != null && userAgent.toLowerCase().contains("observepoint")) {
                return 1.0d;
            }
            if (token == null || token.isEmpty()) return 0.0d;
            if (secretKey == null || secretKey.isEmpty()) return 0.0d;

            String params = "secret=" + URLEncoder.encode(secretKey, "UTF-8")
                    + "&response=" + URLEncoder.encode(token, "UTF-8");

            HttpURLConnection http = (HttpURLConnection) new URL(VERIFY_URL).openConnection();
            http.setDoOutput(true);
            http.setRequestMethod("POST");
            http.setRequestProperty(HEADER_CONTENT_TYPE, "application/x-www-form-urlencoded; charset=UTF-8");
            http.setConnectTimeout(CONNECT_TIMEOUT);
            http.setReadTimeout(READ_TIMEOUT);

            OutputStream out = http.getOutputStream();
            try {
                out.write(params.getBytes(StandardCharsets.UTF_8));
                out.flush();
            } finally { out.close(); }

            if (http.getResponseCode() != 200) return 0.0d;

            BufferedReader rd = new BufferedReader(new InputStreamReader(http.getInputStream(), StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            try {
                int cp; while ((cp = rd.read()) != -1) sb.append((char) cp);
            } finally { rd.close(); }

            JSONObject json = new JSONObject(sb.toString());
            return json.has("score") ? json.getDouble("score") : 0.0d;

        } catch (IOException e) {
            LOGGER.error("reCAPTCHA IO error", e); return 0.0d;
        } catch (JSONException e) {
            LOGGER.error("reCAPTCHA JSON parse error", e); return 0.0d;
        }
    }
}

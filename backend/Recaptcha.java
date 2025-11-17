package com.mnt.axp.common.core.utils;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

import static org.apache.jackrabbit.webdav.DavConstants.HEADER_CONTENT_TYPE;

/**
 * Utility for Google reCAPTCHA v3.
 * This is shared and **must not** block SFMC submissions.
 */
public class Recaptcha {

    private static final Logger LOGGER = LoggerFactory.getLogger(Recaptcha.class);

    public static final String VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";
    public static final int CONNECT_TIMEOUT_MS = 5000;
    public static final int READ_TIMEOUT_MS = 5000;

    /**
     * Validates reCAPTCHA and returns the score.
     *
     * @param secretKey Secret key used to talk to Google
     * @param token     Token from the client
     * @param request   HttpServletRequest (for User-Agent)
     * @return score (0.0 if failed)
     */
    public static double isCaptchaValid(String secretKey, String token, HttpServletRequest request) {
        LOGGER.debug("Inside Recaptcha.isCaptchaValid");

        String userAgent = request != null ? request.getHeader("User-Agent") : null;
        if (userAgent == null || userAgent.isEmpty()) {
            LOGGER.info("User-Agent header is missing or empty");
        } else {
            LOGGER.debug("User agent: {}", userAgent);
        }

        // Example bypass for ObservePoint or other monitors
        if (userAgent != null && userAgent.toLowerCase().contains("observepoint")) {
            LOGGER.info("Bypassing reCAPTCHA for ObservePoint user-agent");
            return 1.0d;
        }

        if (token == null || token.isEmpty()) {
            LOGGER.info("reCAPTCHA token is missing or empty");
            return 0.0d;
        }

        if (secretKey == null || secretKey.isEmpty()) {
            LOGGER.info("reCAPTCHA secret key is missing or empty");
            return 0.0d;
        }

        try {
            String params = "secret=" + URLEncoder.encode(secretKey, StandardCharsets.UTF_8.name()) +
                    "&response=" + URLEncoder.encode(token, StandardCharsets.UTF_8.name());

            LOGGER.debug("Recaptcha URL is: {}", VERIFY_URL);
            LOGGER.debug("Params are: {}", params);

            HttpURLConnection http = (HttpURLConnection) new URL(VERIFY_URL).openConnection();
            http.setDoOutput(true);
            http.setRequestMethod("POST");
            http.setRequestProperty(HEADER_CONTENT_TYPE,
                    "application/x-www-form-urlencoded; charset=UTF-8");
            http.setConnectTimeout(CONNECT_TIMEOUT_MS);
            http.setReadTimeout(READ_TIMEOUT_MS);

            try (OutputStream out = http.getOutputStream()) {
                out.write(params.getBytes(StandardCharsets.UTF_8));
                out.flush();
            }

            int status = http.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                LOGGER.warn("reCAPTCHA verification failed with HTTP status: {}", status);
                try (Scanner scanner = new Scanner(http.getErrorStream()).useDelimiter("\\A")) {
                    String errorBody = scanner.hasNext() ? scanner.next() : "";
                    LOGGER.warn("reCAPTCHA error stream: {}", errorBody);
                }
                return 0.0d;
            }

            BufferedReader rd = new BufferedReader(
                    new InputStreamReader(http.getInputStream(), StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            int cp;
            while ((cp = rd.read()) != -1) {
                sb.append((char) cp);
            }
            String jsonResponse = sb.toString();
            LOGGER.debug("Google reCAPTCHA API Response: {}", jsonResponse);

            JSONObject json = new JSONObject(jsonResponse);
            boolean success = json.optBoolean("success", false);
            double score = json.optDouble("score", 0.0d);
            String action = json.optString("action", "unknown");
            JSONArray errorCodes = json.optJSONArray("error-codes");

            if (!success) {
                if (errorCodes != null && errorCodes.toString().contains("timeout-or-duplicate")) {
                    LOGGER.warn("reCAPTCHA token expired or reused");
                } else {
                    LOGGER.warn("reCAPTCHA verification failed for other reasons");
                }
                return 0.0d;
            }

            LOGGER.info("reCAPTCHA verification result: score={}, action={}, errors={}",
                    score, action, errorCodes != null ? errorCodes.toString() : "none");

            rd.close();
            return score;
        } catch (IOException | JSONException e) {
            LOGGER.error("Error in reCAPTCHA validation", e);
        }

        return 0.0d;
    }

    private Recaptcha() {
        // utility
    }
}

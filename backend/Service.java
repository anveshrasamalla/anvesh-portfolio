package com.mnt.axp.common.core.services.api;

import org.apache.sling.api.request.RequestParameterMap;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Service contract for submitting AEM form data to Salesforce Marketing Cloud (SFMC).
 *
 * Flow implemented by the Impl:
 *  1) Validate reCAPTCHA and compute score
 *  2) Get OAuth token from SFMC
 *  3) Build minimal payload (AEMSubmissionID, TimeStamp, FormID, MessageBody, CaptchaScore)
 *  4) POST to Data Extension (async)
 *  5) Return a compact result for the front-end/servlet
 */
public interface SfmcService {

    /**
     * Submit an AEM form to SFMC.
     *
     * @param params  Sling RequestParameterMap (raw form params)
     * @param request HttpServletRequest (used for reCAPTCHA validation / headers)
     * @return SalesforceResponse with message, error flag, http code, request id, and captcha score
     * @throws IOException on low-level I/O failures
     */
    SalesforceResponse submitToSfmc(RequestParameterMap params, HttpServletRequest request) throws IOException;

    /**
     * Lightweight response DTO that the servlet returns to the front-end.
     * Keep fields simple and predictable for JS.
     */
    class SalesforceResponse {
        /** Human-friendly message, e.g., "Accepted by SFMC" or error detail */
        public String message = "";
        /** True if there was a failure anywhere in the pipeline */
        public boolean error = true;
        /** HTTP-like status we report back (e.g., 202 from SFMC async insert; 500 on failures) */
        public int httpCode = 500;
        /** SFMC async request identifier when available (from POST /rows) */
        public String requestId = "";
        /** reCAPTCHA v3 score (0.0–1.0) for logging/analytics/debugging */
        public double score = 0.0;

        public SalesforceResponse() {}

        public SalesforceResponse(String message, boolean error, int httpCode, String requestId, double score) {
            this.message = message;
            this.error = error;
            this.httpCode = httpCode;
            this.requestId = requestId;
            this.score = score;
        }
    }
}

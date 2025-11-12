package com.mnt.axp.common.core.services.api;

import org.apache.sling.api.request.RequestParameterMap;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Contract for submitting AEM form data to Salesforce Marketing Cloud (SFMC).
 */
public interface SfmcService {

    /**
     * Submit an AEM form to SFMC Data Extension (async insert).
     *
     * @param params  raw Sling params from the servlet
     * @param request HttpServletRequest (used for reCAPTCHA validation)
     * @return SalesforceResponse {message, error, httpCode, requestId, score}
     * @throws IOException on transport/IO failures
     */
    SalesforceResponse submitToSfmc(RequestParameterMap params,
                                    HttpServletRequest request) throws IOException;

    /** Minimal DTO for servlet JSON response. */
    class SalesforceResponse {
        public String  message   = "";
        public boolean error     = true;
        public int     httpCode  = 500;
        public String  requestId = "";
        public double  score     = 0.0;
    }
}

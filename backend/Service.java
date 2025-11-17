package com.mnt.axp.common.core.services;

import org.apache.sling.api.request.RequestParameterMap;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Simple contract: take request params + request and return a compact result
 * after posting to SFMC.
 */
public interface SfmcService {

    SalesforceResponse submitToSfmc(RequestParameterMap params,
                                    HttpServletRequest request) throws IOException;

    /**
     * DTO returned to the servlet and then to the front end.
     */
    class SalesforceResponse {
        public String message = "";
        public boolean error = true;
        public int httpCode = 500;
        public String requestId = "";
        public double score = 0.0;
    }
}

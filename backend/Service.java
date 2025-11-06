package com.mnt.axp.common.core.services.api;

import org.apache.sling.api.request.RequestParameterMap;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/** Simple contract: validate captcha and submit to SFMC. */
public interface SfmcService {

    SalesforceResponse submitToSfmc(
            RequestParameterMap params,
            HttpServletRequest request
    ) throws IOException;

    class SalesforceResponse {
        public String message = "";
        public boolean error = true;
        public double score = 0.0;
    }
}

package com.mnt.axp.common.core.services.api;

import org.apache.sling.api.request.RequestParameterMap;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public interface SfmcService {

    SalesforceResponse submitToSfmc(RequestParameterMap params,
                                    HttpServletRequest request) throws IOException;

    class SalesforceResponse {
        public String  message = "";
        public boolean error   = true;
        public int     httpCode = 500;
        public String  requestId = "";
        public double  score     = 0.0;
    }
}

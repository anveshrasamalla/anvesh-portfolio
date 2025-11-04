package com.mnt.axp.common.core.services.api;

import org.apache.sling.api.request.RequestParameterMap;

import java.io.IOException;
import java.util.List;

public interface SfmcService {

    SalesforceResponse validateAndSubmitForm(
            List<String> searchPaths,
            String formResourceType,
            String urlParameter,
            RequestParameterMap requestParameterMap
    ) throws IOException;

    class SalesforceResponse {
        public String message = "";
        public boolean error = true;
        public double score = 0.0;
        public String redirectUrl = "";
        public java.util.List<String> invalidField = new java.util.ArrayList<>();

        public String getMessage() { return message; }
        public boolean isError() { return error; }
        public double getScore() { return score; }
        public String getRedirectUrl() { return redirectUrl; }
        public java.util.List<String> getInvalidField() { return invalidField; }
    }
}

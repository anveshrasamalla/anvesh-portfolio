package com.mnt.axp.wcm.core.servlets;

import com.mnt.axp.common.core.services.api.SfmcService;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.HttpConstants;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.json.JSONObject;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

import javax.servlet.Servlet;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Handles POST requests from AEM form and routes to SFMC service.
 */
@Component(
        service = Servlet.class,
        property = {
                Constants.SERVICE_DESCRIPTION + "=SFMC Form Submission Servlet",
                "sling.servlet.methods=" + HttpConstants.METHOD_POST,
                "sling.servlet.paths=/bin/wcm/sfmc"
        }
)
public class SfmcServlet extends SlingAllMethodsServlet {

    @Reference private transient SfmcService sfmcService;

    @Override
    protected void doPost(final SlingHttpServletRequest req, final SlingHttpServletResponse res)
            throws IOException {

        SfmcService.SalesforceResponse r = sfmcService.submitToSfmc(req.getRequestParameterMap(), req);

        JSONObject json = new JSONObject();
        json.put("message", r.message);
        json.put("error", r.error);
        json.put("httpCode", r.httpCode);
        json.put("requestId", r.requestId);

        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        res.setStatus(200);

        try (PrintWriter w = res.getWriter()) {
            w.write(json.toString());
        }
    }
}

package com.mnt.axp.wcm.core.servlets;

import com.mnt.axp.common.core.services.SfmcService;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.HttpConstants;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.xss.XSSFilter;
import org.json.JSONException;
import org.json.JSONObject;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Servlet;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * POST /bin/wcm/sfmc
 *
 * Entry point for AEM forms to talk to SFMC.
 */
@Component(
        service = Servlet.class,
        property = {
                Constants.SERVICE_DESCRIPTION + "=SFMC Servlet (Direct Post)",
                "sling.servlet.methods=" + HttpConstants.METHOD_POST,
                "sling.servlet.paths=/bin/wcm/sfmc"
        }
)
public class SfmcServlet extends SlingAllMethodsServlet {

    private static final Logger LOGGER = LoggerFactory.getLogger(SfmcServlet.class);

    @Reference
    private transient SfmcService sfmcService;

    @Reference
    private transient XSSFilter xss;

    @Override
    protected void doPost(final SlingHttpServletRequest req,
                          final SlingHttpServletResponse res) throws IOException {

        LOGGER.debug("[SFMC] Servlet doPost called");

        SfmcService.SalesforceResponse r = sfmcService.submitToSfmc(
                req.getRequestParameterMap(),
                req // Sling request is-a HttpServletRequest
        );

        JSONObject json = new JSONObject();
        try {
            json.put("message", r.message);
            json.put("error", r.error);
            json.put("httpCode", r.httpCode);
            json.put("requestId", r.requestId);
        } catch (JSONException e) {
            // This should not really fail; if it does, surface a generic error
            LOGGER.error("[SFMC] Failed to build JSON response", e);
            res.sendError(500, "Internal error building JSON response");
            return;
        }

        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        res.setStatus(r.error ? 500 : 200);

        PrintWriter w = res.getWriter();
        // XSSFilter encodes quotes as &quot;, revert that so front-end gets valid JSON
        w.write(xss.filter(json.toString()).replace("&quot;", "\""));
        w.flush();

        LOGGER.debug("[SFMC] Servlet response sent. error={}, httpCode={}, requestId={}",
                r.error, r.httpCode, r.requestId);
    }
}

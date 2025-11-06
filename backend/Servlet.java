package com.mnt.axp.wcm.core.servlets;

import com.mnt.axp.common.core.services.api.SfmcService;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.HttpConstants;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.xss.XSSFilter;
import org.json.JSONObject;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

import javax.servlet.Servlet;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Simple entry: POST /bin/wcm/sfmc
 * Sends request params to service and returns compact JSON.
 */
@Component(
        service = Servlet.class,
        property = {
                Constants.SERVICE_DESCRIPTION + "=SFMC Servlet (Simple Direct Post)",
                "sling.servlet.methods=" + HttpConstants.METHOD_POST,
                "sling.servlet.paths=/bin/wcm/sfmc"
        }
)
public class SfmcServlet extends SlingAllMethodsServlet {

    @Reference private transient SfmcService sfmcService;
    @Reference private transient XSSFilter xssFilter;

    @Override
    protected void doPost(final SlingHttpServletRequest req,
                          final SlingHttpServletResponse res) throws IOException {

        SfmcService.SalesforceResponse r = sfmcService.submitToSfmc(
                req.getRequestParameterMap(),
                req // Sling request is-a HttpServletRequest
        );

        JSONObject json = new JSONObject();
        json.put("message", r.message);
        json.put("error", r.error);
        json.put("score", r.score);

        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        res.setStatus(r.error ? 500 : 200);

        PrintWriter w = res.getWriter();
        // sanitize just in case (though JSON values are ours)
        w.write(xssFilter.filter(json.toString()).replace("&quot;", "\""));
        w.flush();
    }
}

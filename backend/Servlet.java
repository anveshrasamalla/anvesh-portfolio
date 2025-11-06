package com.mnt.axp.wcm.core.servlets;

import com.mnt.axp.common.core.services.api.SfmcService;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.HttpConstants;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.xss.XSSFilter;
import org.json.JSONObject;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.*;

import javax.servlet.Servlet;
import java.io.IOException;
import java.io.PrintWriter;

@Component(
    service = Servlet.class,
    property = {
        Constants.SERVICE_DESCRIPTION + "=SFMC Servlet (Simple Direct Post)",
        "sling.servlet.methods=" + HttpConstants.METHOD_POST,
        "sling.servlet.paths=/bin/wcm/sfmc"
    }
)
public class SfmcServlet extends SlingAllMethodsServlet {

    @Reference private SfmcService sfmc;
    @Reference private XSSFilter xss;

    @Override
    protected void doPost(SlingHttpServletRequest req, SlingHttpServletResponse res) throws IOException {
        SfmcService.SalesforceResponse r = sfmc.submitToSfmc(req.getRequestParameterMap(), req);
        JSONObject json = new JSONObject();
        json.put("message", r.message);
        json.put("error", r.error);
        json.put("score", r.score);

        res.setContentType("application/json");
        res.setStatus(r.error ? 500 : 200);
        PrintWriter w = res.getWriter();
        w.write(xss.filter(json.toString()).replace("&quot;","\""));
        w.flush();
    }
}

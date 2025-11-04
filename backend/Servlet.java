package com.mnt.axp.wcm.core.servlets;

import com.mnt.axp.common.core.services.api.SfmcService;
import org.apache.commons.lang3.StringUtils;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.HttpConstants;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.xss.XSSFilter;
import org.json.JSONObject;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Servlet;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;

@Component(
        service = Servlet.class,
        property = {
                Constants.SERVICE_DESCRIPTION + "=WCM Salesforce Marketing Cloud Servlet",
                "sling.servlet.methods=" + HttpConstants.METHOD_POST,
                "sling.servlet.paths=" + SfmcServlet.SERVLET_PATH
        }
)
public class SfmcServlet extends SlingAllMethodsServlet {

    public static final String SERVLET_PATH = "/bin/wcm/sfmc";
    private static final Logger LOG = LoggerFactory.getLogger(SfmcServlet.class);
    private static final List<String> SEARCH_PATHS = Arrays.asList(
            "/content/mtb-web/en",
            "/content/experience-fragments/mtb-web",
            "/content/mtb-web/en-v2"
    );
    private static final String FORM_RESOURCE = "axp-common/components/form/form-container/v1/form-container";
    private static final String REQUIRED_URL = "https://www.mtb.com";

    @Reference
    private transient SfmcService sfmcService;

    @Reference
    private transient XSSFilter xssFilter;

    @Override
    protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response) throws IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        JSONObject json = new JSONObject();
        try (PrintWriter writer = response.getWriter()) {
            String componentType = request.getParameter("componentType");
            String formType = StringUtils.defaultIfBlank(componentType, FORM_RESOURCE);
            LOG.info("📨 SFMC Form Submit [{}]", formType);

            SfmcService.SalesforceResponse sfmcResp = sfmcService.validateAndSubmitForm(
                    SEARCH_PATHS, formType, REQUIRED_URL, request.getRequestParameterMap());

            json.put("message", sfmcResp.getMessage());
            json.put("score", sfmcResp.getScore());
            json.put("invalidFields", sfmcResp.getInvalidField());
            json.put("redirectUrl", sfmcResp.getRedirectUrl());
            json.put("error", sfmcResp.isError());
            writer.write(xssFilter.filter(json.toString()).replace("&quot;", "\""));
            writer.flush();

            response.setStatus(sfmcResp.isError() ? 500 : 200);
        } catch (Exception e) {
            LOG.error("❌ SFMC Servlet Error", e);
            response.sendError(500, e.getMessage());
        }
    }
}

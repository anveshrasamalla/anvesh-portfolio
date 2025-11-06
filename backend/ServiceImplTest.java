package com.mnt.axp.common.core.services.impl;

import com.google.gson.JsonObject;
import com.mnt.axp.common.core.services.api.SfmcService;
import com.mnt.axp.common.core.utils.ApiClient;
import com.mnt.axp.common.core.utils.Recaptcha;
import io.wcm.testing.mock.aem.junit5.AemContext;
import io.wcm.testing.mock.aem.junit5.AemContextExtension;
import org.apache.sling.api.request.RequestParameter;
import org.apache.sling.api.request.RequestParameterMap;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.osgi.service.component.annotations.Activate;

import java.io.IOException;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link SfmcServiceImpl}.
 * Tests SFMC auth + form validation logic with AEM mocks.
 */
@ExtendWith(AemContextExtension.class)
public class SfmcServiceImplTest {

    private final AemContext context = new AemContext();

    @Mock
    private ResourceResolverFactory resolverFactory;

    @Mock
    private ApiClient apiClient;

    private SfmcServiceImpl service;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        service = new SfmcServiceImpl();

        // Mock OSGi config
        SfmcServiceImpl.Config config = new SfmcServiceImpl.Config() {
            @Override public Class<? extends java.lang.annotation.Annotation> annotationType() { return SfmcServiceImpl.Config.class; }
            @Override public String sfmc_auth_base() { return "https://mock.auth"; }
            @Override public String sfmc_rest_base() { return "https://mock.rest"; }
            @Override public String sfmc_client_id() { return "client_id"; }
            @Override public String sfmc_client_secret() { return "client_secret"; }
            @Override public String sfmc_account_id() { return "acc"; }
            @Override public String sfmc_default_de_key() { return "defaultDE"; }
            @Override public String greCAPTCHA_secretKey() { return "secret"; }
            @Override public int timeout_ms() { return 5000; }
            @Override public boolean debug_logs() { return true; }
        };

        // Activate service manually
        service.activate(config);
        context.registerService(ResourceResolverFactory.class, resolverFactory);
    }

    @Test
    void testAuthSuccess() throws Exception {
        // Mock successful token API response
        JsonObject tokenResponse = new JsonObject();
        tokenResponse.addProperty("access_token", "mock_token");

        SfmcServiceImpl mockService = spy(service);
        doReturn(tokenResponse)
                .when(mockService)
                .authenticateResponse(any());

        String token = mockService.authenticate();
        assertNotNull(token);
    }

    @Test
    void testValidateFormWithInvalidId() throws IOException {
        RequestParameterMap map = mock(RequestParameterMap.class);
        when(map.getValue("aemformid")).thenReturn(mock(RequestParameter.class));
        when(map.getValue("aemformid").getString()).thenReturn("abc"); // invalid numeric pattern

        SfmcService.SalesforceResponse resp = service.validateAndSubmitForm(
                Collections.singletonList("/content/test"),
                "axp-common/components/form/form-container/v1/form-container",
                "https://mtb.com",
                map);

        assertTrue(resp.error);
        assertEquals("Invalid or missing Form ID.", resp.message);
    }

    @Test
    void testCaptchaValidationBypass() {
        double score = Recaptcha.isCaptchaValid("secret", "public", "mock", context.request());
        assertTrue(score >= 0.0);
    }

    @Test
    void testBuildPayloadStructure() throws IOException {
        // Create valid parameters
        Map<String, String> params = new HashMap<>();
        params.put("Email", "test@example.com");
        params.put("FirstName", "John");
        params.put("LastName", "Doe");
        params.put("FormId", "1001");
        params.put("CaptchaScore", "0.9");

        // Call private method through reflection
        var method = SfmcServiceImpl.class.getDeclaredMethod("buildSfmcPayload", Map.class);
        method.setAccessible(true);
        Object result = method.invoke(service, params);

        assertNotNull(result);
        assertTrue(result.toString().contains("EmailAddress"));
    }

    @Test
    void testAuthenticateFailure() {
        SfmcServiceImpl badService = new SfmcServiceImpl();
        SfmcServiceImpl.Config cfg = mock(SfmcServiceImpl.Config.class);
        when(cfg.sfmc_auth_base()).thenReturn("https://bad.auth");
        when(cfg.sfmc_rest_base()).thenReturn("https://bad.rest");
        when(cfg.sfmc_client_id()).thenReturn("x");
        when(cfg.sfmc_client_secret()).thenReturn("y");
        when(cfg.sfmc_account_id()).thenReturn("z");
        when(cfg.sfmc_default_de_key()).thenReturn("default");
        when(cfg.greCAPTCHA_secretKey()).thenReturn("key");
        when(cfg.timeout_ms()).thenReturn(3000);
        when(cfg.debug_logs()).thenReturn(true);

        badService.activate(cfg);
        assertThrows(RuntimeException.class, badService::authenticate);
    }
}

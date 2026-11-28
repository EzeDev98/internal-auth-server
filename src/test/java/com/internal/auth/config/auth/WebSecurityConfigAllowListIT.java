package com.internal.auth.config.auth;

import com.internal.auth.testsupport.IntegrationTestBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;

/** Verifies the security permitAll list matches the real endpoints. */
class WebSecurityConfigAllowListIT extends IntegrationTestBase {

    @Autowired
    private RequestMappingHandlerMapping handlerMapping;

    @Value("${app.title}")
    private String appTitle;

    private Set<String> expectedPublic;

    private record Endpoint(HttpMethod method, String path) {
        @Override
        public String toString() {
            return method + " " + path;
        }
    }

    @BeforeEach
    void buildExpectedPublicList() {
        expectedPublic = new LinkedHashSet<>();
        Set.of(
                "/auth/register", "/auth/login",
                "/auth/activate", "/auth/resend-activation",
                "/auth/verify-phone", "/auth/resend-phone-verification",
                "/password-reset/request", "/password-reset/verify-otp", "/password-reset/complete",
                "/admin/register", "/admin/login"
        ).forEach(path -> expectedPublic.add(new Endpoint(HttpMethod.POST, appTitle + path).toString()));

        expectedPublic.add(new Endpoint(HttpMethod.GET, appTitle + "/auth/activate").toString());
    }

    @Test
    void everyOwnEndpoint_isPublicIfAndOnlyIfWebSecurityConfigPermitsIt() throws Exception {
        Set<String> failures = new LinkedHashSet<>();

        for (Map.Entry<RequestMappingInfo, HandlerMethod> entry : handlerMapping.getHandlerMethods().entrySet()) {
            RequestMappingInfo info = entry.getKey();
            Set<RequestMethod> methods = info.getMethodsCondition().getMethods();

            for (String pattern : info.getPatternValues()) {
                if (!pattern.startsWith(appTitle)) {
                    continue;
                }

                for (RequestMethod requestMethod : methods) {
                    HttpMethod httpMethod = HttpMethod.valueOf(requestMethod.name());
                    String concretePath = pattern.replaceAll("\\{[^/{}]+}", "diff-test-value");
                    String key = new Endpoint(httpMethod, pattern).toString();
                    boolean shouldBePublic = expectedPublic.contains(key);

                    MvcResult result = mockMvc.perform(request(httpMethod, concretePath)).andReturn();
                    int status = result.getResponse().getStatus();
                    boolean rejectedAsUnauthenticated = status == 401;

                    if (shouldBePublic == rejectedAsUnauthenticated) {
                        failures.add(key + " -> expected public=" + shouldBePublic + " but got status " + status);
                    }
                }
            }
        }

        assertThat(failures)
                .as("WebSecurityConfig permitAll list vs actual endpoints under " + appTitle)
                .isEmpty();
    }
}

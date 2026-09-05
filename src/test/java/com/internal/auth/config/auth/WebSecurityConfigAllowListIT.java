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

/**
 * Step 11A. A "diff test" between {@link WebSecurityConfig#securityFilterChain}'s
 * own permitAll() list and the actual set of endpoints this app exposes
 * under app.title ("/api/v1"): every path+method pair marked permitAll
 * there must genuinely be reachable with no bearer token, and - the more
 * dangerous direction, since it's permitAll-by-accident rather than by
 * decision - every other path+method pair this app's own controllers map
 * must reject an unauthenticated caller with 401.
 *
 * <p>Endpoints are discovered at runtime from {@link RequestMappingHandlerMapping}
 * rather than hand-listed here, so a new mapping added to any controller
 * under app.title is automatically pulled into this test the next time it
 * runs: it fails closed (demands a 401) until WebSecurityConfig and
 * EXPECTED_PUBLIC below are both updated deliberately. That is the
 * intended failure mode - this test is meant to be re-run, and to fail
 * loudly, on every change to WebSecurityConfig, per the roadmap.
 *
 * <p>Scoped to paths starting with app.title only. Actuator (Step 14E),
 * Swagger/robots.txt, the OPTIONS-preflight matcher and the malicious-probe
 * denyAll matcher are not this app's own {@code RequestMappingHandlerMapping}
 * entries and are covered elsewhere - out of scope for this diff.
 * "/api/v1/otp/**" and "/api/v1/logout/backchannel" are in
 * WebSecurityConfig's permitAll list but have no implemented controller yet
 * (confirmed pre-wiring stubs per that file's own comments), so there is
 * nothing to discover or exercise for them here - deliberately absent from
 * EXPECTED_PUBLIC below; add them once a real endpoint exists.
 */
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
                "/auth/register", "/auth/login", "/auth/login/verify-otp",
                "/auth/activate", "/auth/resend-activation",
                "/auth/verify-phone", "/auth/resend-phone-verification",
                "/password-reset/request", "/password-reset/verify-otp", "/password-reset/complete",
                "/admin/register", "/admin/login", "/admin/login/verify-otp"
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
                    continue; // out of scope - see class Javadoc
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

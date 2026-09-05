package com.internal.auth.config;

import com.internal.auth.testsupport.IntegrationTestBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Step 11E. management.endpoints.web.exposure.include in application.properties
 * explicitly limits actuator's web exposure to health,info,metrics,prometheus -
 * this proves that limit actually holds against a real running server on the
 * separate management port (management.server.port, 8081), not just that the
 * property is set. Requires a genuinely running embedded server rather than
 * MockMvc: the management port is a distinct embedded connector with its own
 * DispatcherServlet, outside the main WebApplicationContext MockMvc dispatches
 * into directly - IntegrationTestBase's DEFINED_PORT webEnvironment (see its
 * own javadoc) is what makes a real loopback HTTP call to localhost work here
 * at all. Uses the plain JDK HttpClient rather than a Spring Boot test HTTP
 * client - Boot 4's per-feature test-starter split (spring-boot-starter-restclient-test
 * et al., see pom.xml) relocated several test-only classes, and this avoids
 * depending on knowing that new package path correctly.
 *
 * WebSecurityConfig's own javadoc on EndpointRequest.toAnyEndpoint() notes
 * this app's security filter chain applies across every port it listens on,
 * confirmed the hard way - so a sensitive endpoint being unreachable here
 * must come from Boot never registering a web handler for it in the first
 * place (a plain 404), not from a security rule that could later be loosened.
 */
class ActuatorManagementPortIT extends IntegrationTestBase {

    private static final HttpClient HTTP_CLIENT = HttpClient.newHttpClient();

    @Value("${management.server.port}")
    private int managementPort;

    private HttpResponse<String> getManagementPath(String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + managementPort + path))
                .GET()
                .build();
        return HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void health_info_metrics_andPrometheus_areReachable() throws Exception {
        assertThat(getManagementPath("/actuator/health").statusCode()).isEqualTo(200);
        assertThat(getManagementPath("/actuator/info").statusCode()).isEqualTo(200);
        assertThat(getManagementPath("/actuator/metrics").statusCode()).isEqualTo(200);
        assertThat(getManagementPath("/actuator/prometheus").statusCode()).isEqualTo(200);
    }

    @Test
    void sensitiveAndUnlistedEndpoints_areNotExposed() throws Exception {
        for (String path : new String[]{
                "/actuator/env", "/actuator/heapdump", "/actuator/beans",
                "/actuator/mappings", "/actuator/configprops", "/actuator/shutdown"
        }) {
            assertThat(getManagementPath(path).statusCode())
                    .as("%s must not be exposed - only health,info,metrics,prometheus are", path)
                    .isEqualTo(404);
        }
    }
}

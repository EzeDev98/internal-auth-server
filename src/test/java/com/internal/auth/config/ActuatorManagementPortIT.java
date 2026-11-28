package com.internal.auth.config;

import com.internal.auth.testsupport.IntegrationTestBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/** Verifies which actuator endpoints are exposed over the web. */
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

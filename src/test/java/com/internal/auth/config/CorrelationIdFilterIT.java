package com.internal.auth.config;

import com.internal.auth.testsupport.IntegrationTestBase;
import org.junit.jupiter.api.Test;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Step 11D. CorrelationIdFilter's own javadoc explains it deliberately has
 * no @Order, relying on Micrometer Tracing's own instrumentation having
 * already started the current span by the time it runs - this is the test
 * that actually proves tracer.currentSpan() is non-null for a real request
 * instead of just trusting that ordering argument. Checked on both a
 * public (200) and a rejected-unauthenticated (401) response, since the
 * filter runs regardless of what WebSecurityConfig or the controller
 * decides afterward - it sets the header before calling down the chain.
 */
class CorrelationIdFilterIT extends IntegrationTestBase {

    @Test
    void publicEndpointResponse_carriesTheTraceIdHeader() throws Exception {
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(header().exists("X-Trace-Id"));
    }

    @Test
    void unauthenticatedRejectionResponse_stillCarriesTheTraceIdHeader() throws Exception {
        mockMvc.perform(delete("/api/v1/session"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("X-Trace-Id"));
    }
}

package com.internal.auth.config;

import com.internal.auth.testsupport.IntegrationTestBase;
import org.junit.jupiter.api.Test;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Verifies the trace ID response header set by CorrelationIdFilter. */
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

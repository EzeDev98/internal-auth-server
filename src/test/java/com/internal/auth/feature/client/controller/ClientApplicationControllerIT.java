package com.internal.auth.feature.client.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.feature.client.dto.CreateClientApplicationRequest;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.TestTokenMinter;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

import static com.internal.auth.testsupport.ApiResponseAssertions.success;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Tag;

/** Integration tests for ClientApplicationController. */
@Tag("security-boundary")
class ClientApplicationControllerIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private TestTokenMinter testTokenMinter;
    @Autowired
    private ObjectMapper objectMapper;

    private ClientApplication callerClient;

    @BeforeEach
    void persistCallerClient() {
        callerClient = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
    }

    @Test
    void createClient_withNoToken_isUnauthorized() throws Exception {
        CreateClientApplicationRequest request =
                new CreateClientApplicationRequest("new-client-13f", "New Client 13F", null, null, null, null);

        mockMvc.perform(post("/api/v1/client-applications")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void createClient_withNonAdminToken_isForbidden() throws Exception {
        String nonAdminToken = testTokenMinter.mintAccessToken(callerClient.getId(), "non_admin_13f", List.of("basic_access"));
        CreateClientApplicationRequest request =
                new CreateClientApplicationRequest("new-client-13f-2", "New Client 13F", null, null, null, null);

        mockMvc.perform(post("/api/v1/client-applications")
                        .header("Authorization", "Bearer " + nonAdminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    void createClient_withAdminToken_returns201WithAFreshSecret() throws Exception {
        String adminToken = testTokenMinter.mintAccessToken(callerClient.getId(), "admin_13f", List.of("create-admin"));
        CreateClientApplicationRequest request =
                new CreateClientApplicationRequest("new-client-13f-3", "New Client 13F", null, null, null, null);

        mockMvc.perform(post("/api/v1/client-applications")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(success())
                .andExpect(jsonPath("$.data.clientId").value("new-client-13f-3"))
                .andExpect(jsonPath("$.data.clientSecret").isNotEmpty());

        ClientApplication saved = clientApplicationRepository.findByClientId("new-client-13f-3").orElseThrow();
        assertThat(saved.getClientSecretHash()).isNotBlank();
    }

    @Test
    void rotateSecret_withNoToken_isUnauthorized() throws Exception {
        ClientApplication target = clientApplicationRepository.save(
                ClientApplicationTestDataBuilder.aClientApplication()
                        .withClientSecretHash(passwordEncoder.encode("old-secret-13f"))
                        .build());

        mockMvc.perform(post("/api/v1/client-applications/{clientId}/rotate-secret", target.getClientId()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rotateSecret_withNonAdminToken_isForbidden() throws Exception {
        ClientApplication target = clientApplicationRepository.save(
                ClientApplicationTestDataBuilder.aClientApplication()
                        .withClientSecretHash(passwordEncoder.encode("old-secret-13f-2"))
                        .build());
        String nonAdminToken = testTokenMinter.mintAccessToken(callerClient.getId(), "non_admin_13f", List.of("basic_access"));

        mockMvc.perform(post("/api/v1/client-applications/{clientId}/rotate-secret", target.getClientId())
                        .header("Authorization", "Bearer " + nonAdminToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void rotateSecret_withAdminToken_returnsANewSecretAndThePreviousOneStopsWorking() throws Exception {
        String oldSecret = "old-secret-13f-3";
        ClientApplication target = clientApplicationRepository.save(
                ClientApplicationTestDataBuilder.aClientApplication()
                        .withClientSecretHash(passwordEncoder.encode(oldSecret))
                        .build());
        String adminToken = testTokenMinter.mintAccessToken(callerClient.getId(), "admin_13f", List.of("create-admin"));

        String responseBody = mockMvc.perform(post("/api/v1/client-applications/{clientId}/rotate-secret", target.getClientId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(success())
                .andExpect(jsonPath("$.data.clientId").value(target.getClientId()))
                .andExpect(jsonPath("$.data.clientSecret").isNotEmpty())
                .andReturn().getResponse().getContentAsString();

        String newSecret = objectMapper.readTree(responseBody).path("data").path("clientSecret").asText();
        assertThat(newSecret).isNotBlank().isNotEqualTo(oldSecret);

        ClientApplication reloaded = clientApplicationRepository.findById(target.getId()).orElseThrow();
        assertThat(passwordEncoder.matches(oldSecret, reloaded.getClientSecretHash())).isFalse();
        assertThat(passwordEncoder.matches(newSecret, reloaded.getClientSecretHash())).isTrue();
    }
}

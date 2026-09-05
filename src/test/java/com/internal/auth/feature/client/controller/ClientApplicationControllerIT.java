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

/**
 * Step 13F (last item of Step 13): ClientApplicationController's create and
 * rotate-secret endpoints are both @PreAuthorize(Roles.HAS_ADMIN), and
 * CreateClientApplicationResponse's own class Javadoc is explicit that
 * clientSecret "carries the one and only time the raw secret is ever
 * available" - only its BCrypt hash is ever persisted, so a rotated
 * client's PREVIOUS secret must never reappear anywhere in the response and
 * must genuinely stop authenticating once rotated.
 *
 * The rotate-secret admin-token case seeds a client with a known raw
 * secret, then asserts three things together: the response's new secret is
 * never equal to that known old one (nothing "leaks" the previous value
 * back), the old secret's hash no longer verifies against the persisted
 * row afterward, and the new secret's hash does - proving the rotation is
 * both real and one-way, not just a response-shape check.
 *
 * Only calls rotate-secret once with a genuine admin token -
 * AppConstant.MAX_CLIENT_SECRET_ROTATE_REQUEST is 5 per IP per day (the
 * rate limiter runs inside the method body, after @PreAuthorize already
 * passed, so the no-token/non-admin-token cases below never touch it).
 */
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
        // The client application backing the caller's own minted token -
        // unrelated to any client application a test creates/rotates below.
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

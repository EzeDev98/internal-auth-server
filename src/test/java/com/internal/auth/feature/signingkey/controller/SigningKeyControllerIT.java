package com.internal.auth.feature.signingkey.controller;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.TestTokenMinter;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

import static com.internal.auth.testsupport.ApiResponseAssertions.success;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Tag;

/** Integration tests for SigningKeyController. */
@Tag("security-boundary")
class SigningKeyControllerIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private TestTokenMinter testTokenMinter;

    private ClientApplication client;

    @BeforeEach
    void persistClient() {
        client = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
    }

    @Test
    void rotate_withNoToken_isUnauthorized() throws Exception {
        mockMvc.perform(post("/api/v1/admin/signing-keys/rotate"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rotate_withNonAdminToken_isForbidden() throws Exception {
        String nonAdminToken = testTokenMinter.mintAccessToken(client.getId(), "non_admin_13d", List.of("basic_access"));

        mockMvc.perform(post("/api/v1/admin/signing-keys/rotate")
                        .header("Authorization", "Bearer " + nonAdminToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void rotate_withAdminToken_returns200AndMakesTheNewKeyCurrent() throws Exception {
        String adminToken = testTokenMinter.mintAccessToken(client.getId(), "admin_13d", List.of("create-admin"));

        mockMvc.perform(post("/api/v1/admin/signing-keys/rotate")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(success())
                .andExpect(jsonPath("$.data.kid").exists())
                .andExpect(jsonPath("$.data.current").value(true));
    }
}

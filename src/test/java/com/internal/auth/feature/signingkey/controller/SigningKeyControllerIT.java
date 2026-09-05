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

/**
 * Step 13D (SigningKeyController slice): POST /admin/signing-keys/rotate is
 * @PreAuthorize(Roles.HAS_ADMIN) - admin-only JWT signing-key rotation.
 *
 * Only the admin-token case actually reaches SigningKeyService#rotate() and
 * its rate limiter (checkRateLimit runs inside the method body, after
 * @PreAuthorize already passed) - the no-token/non-admin-token cases below
 * never touch it. AppConstant.MAX_SIGNING_KEY_ROTATE_REQUEST is 5 per IP per
 * day, so this class calls the endpoint with a real admin token exactly
 * once to stay well under that threshold.
 */
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

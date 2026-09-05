package com.internal.auth.feature.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.dto.SetMfaRequest;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.TestTokenMinter;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

import java.util.List;

import static com.internal.auth.testsupport.ApiResponseAssertions.success;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Tag;

/**
 * Step 13D (MfaAdminController slice): PUT /users/{username}/mfa is
 * @PreAuthorize(Roles.HAS_ADMIN) - admin-only MFA toggle, resolving the
 * target user via an admin-supplied clientId (query param) rather than the
 * caller's own JWT (that's MfaSelfServiceController's job, Step 13E).
 *
 * The seeded user has a verified phone number so the admin-token/enable
 * case reaches a genuine success (MfaAdminServiceImpl#setMfaEnabled throws
 * BadRequestException for enabling MFA against an unverified/absent phone
 * number - not the concern of this admin-only-enforcement test).
 */
@Tag("security-boundary")
class MfaAdminControllerIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private TestTokenMinter testTokenMinter;
    @Autowired
    private ObjectMapper objectMapper;

    private ClientApplication client;

    @BeforeEach
    void persistClient() {
        client = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
    }

    private User persistVerifiedPhoneUser() throws Exception {
        return userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(client.getId())
                .withPhoneNumber("+23480001301")
                .withPhoneVerified(true)
                .build());
    }

    @Test
    void setMfa_withNoToken_isUnauthorized() throws Exception {
        User user = persistVerifiedPhoneUser();
        SetMfaRequest request = new SetMfaRequest(true);

        mockMvc.perform(put("/api/v1/users/{username}/mfa", user.getUsername())
                        .param("clientId", client.getClientId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void setMfa_withNonAdminToken_isForbidden() throws Exception {
        User user = persistVerifiedPhoneUser();
        String nonAdminToken = testTokenMinter.mintAccessToken(client.getId(), "non_admin_13d", List.of("basic_access"));
        SetMfaRequest request = new SetMfaRequest(true);

        mockMvc.perform(put("/api/v1/users/{username}/mfa", user.getUsername())
                        .param("clientId", client.getClientId())
                        .header("Authorization", "Bearer " + nonAdminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    void setMfa_withAdminToken_enablesMfaForTheUser() throws Exception {
        User user = persistVerifiedPhoneUser();
        String adminToken = testTokenMinter.mintAccessToken(client.getId(), "admin_13d", List.of("create-admin"));
        SetMfaRequest request = new SetMfaRequest(true);

        mockMvc.perform(put("/api/v1/users/{username}/mfa", user.getUsername())
                        .param("clientId", client.getClientId())
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(success());

        assertThat(userRepository.findById(user.getId()).orElseThrow().isMfaEnabled()).isTrue();
    }
}

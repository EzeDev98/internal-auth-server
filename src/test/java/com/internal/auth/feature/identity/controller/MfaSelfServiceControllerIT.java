package com.internal.auth.feature.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.dto.request.SetMfaRequest;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Tag;

/**
 * Step 13E (MfaSelfServiceController slice): POST /mfa/self takes no
 * username or clientId at all - both are resolved from the caller's own
 * JWT (AuthenticationHelper#getCurrentUsername/getCurrentClientApplicationId),
 * so there is no parameter through which a caller could even attempt to
 * target another user's account. There's also deliberately no
 * @PreAuthorize role check beyond "authenticated" (see the controller's
 * own class Javadoc - gating this on a role like basic_access would break
 * it for a freshly-registered user with no default role yet), so the token
 * below carries no roles at all to prove that.
 */
@Tag("security-boundary")
class MfaSelfServiceControllerIT extends IntegrationTestBase {

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

    private User persistVerifiedPhoneUser(String phoneNumber) {
        return userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(client.getId())
                .withPhoneNumber(phoneNumber)
                .withPhoneVerified(true)
                .build());
    }

    @Test
    void setMfaForSelf_withNoToken_isUnauthorized() throws Exception {
        SetMfaRequest request = new SetMfaRequest(true);

        mockMvc.perform(post("/api/v1/mfa/self")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void setMfaForSelf_withARoleLessToken_enablesMfaForTheCallerOnly() throws Exception {
        User caller = persistVerifiedPhoneUser("+23480001401");
        User otherUser = persistVerifiedPhoneUser("+23480001402");
        String callerToken = testTokenMinter.mintAccessToken(client.getId(), caller.getUsername(), List.of());
        SetMfaRequest request = new SetMfaRequest(true);

        mockMvc.perform(post("/api/v1/mfa/self")
                        .header("Authorization", "Bearer " + callerToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        assertThat(userRepository.findById(caller.getId()).orElseThrow().isMfaEnabled()).isTrue();
        assertThat(userRepository.findById(otherUser.getId()).orElseThrow().isMfaEnabled()).isFalse();
    }
}

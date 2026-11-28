package com.internal.auth.feature.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.common.reset.OtpResetEngine;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.dto.request.ResendActivationRequest;
import com.internal.auth.feature.identity.model.EmailVerificationToken;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.EmailVerificationTokenRepository;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.internal.auth.testsupport.ApiResponseAssertions.success;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Integration tests for EmailVerificationController. */
class EmailVerificationControllerIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private EmailVerificationTokenRepository tokenRepository;
    @Autowired
    private OtpResetEngine otpResetEngine;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private ObjectMapper objectMapper;

    private String basicAuthHeader(String clientId, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private ClientApplication persistClientWithSecret(String plaintextSecret) {
        return clientApplicationRepository.save(
                ClientApplicationTestDataBuilder.aClientApplication()
                        .withClientSecretHash(passwordEncoder.encode(plaintextSecret))
                        .build());
    }

    @Test
    void activateViaLink_withAValidToken_marksTheAccountsEmailVerified() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        User user = userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(client.getId())
                .withEmail("activate-12a@user.com")
                .withEmailVerified(false)
                .build());

        String rawToken = "12a-raw-activation-token-" + user.getId();
        EmailVerificationToken token = new EmailVerificationToken();
        token.setUserId(user.getId());
        otpResetEngine.populateNewToken(token, rawToken, 60);
        tokenRepository.save(token);

        mockMvc.perform(get("/api/v1/auth/activate").param("token", rawToken))
                .andExpect(status().isOk())
                .andExpect(success());

        assertThat(userRepository.findById(user.getId()).orElseThrow().isEmailVerified()).isTrue();
    }

    @Test
    void resendActivation_withValidClientCredentials_returnsTheGenericSuccessMessage() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        ResendActivationRequest request = new ResendActivationRequest("someone@user.com");

        mockMvc.perform(post("/api/v1/auth/resend-activation")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "correct-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(success());
    }

    @Test
    void resendActivation_withNoClientCredentials_isUnauthorized() throws Exception {
        ResendActivationRequest request = new ResendActivationRequest("someone-else@user.com");

        mockMvc.perform(post("/api/v1/auth/resend-activation")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void resendActivation_withWrongClientSecret_isUnauthorized() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        ResendActivationRequest request = new ResendActivationRequest("someone-else-2@user.com");

        mockMvc.perform(post("/api/v1/auth/resend-activation")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "wrong-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }
}

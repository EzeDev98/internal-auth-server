package com.internal.auth.feature.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.dto.request.LoginRequest;
import com.internal.auth.feature.identity.model.User;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Step 12A (LoginController slice). Happy path plus the same HTTP Basic
 * client-credential enforcement RegistrationControllerIT covers -
 * LoginController resolves the caller's ClientApplication the identical
 * way (see LoginController's own class Javadoc). The seeded User uses
 * UserTestDataBuilder's defaults (enabled, phoneVerified=true, no email,
 * mfaEnabled=false) so login completes in one step with no MFA branch,
 * exactly like TestTokenMinter avoids needing a real login round-trip for
 * every other test in this suite - here the round-trip itself is the point.
 */
class LoginControllerIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private UserRepository userRepository;
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
    void login_withValidCredentialsAndClientAuth_returnsAnAccessToken() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        User user = userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(client.getId())
                .withPasswordHash(passwordEncoder.encode("Passw0rd!"))
                .build());

        LoginRequest request = new LoginRequest(user.getUsername(), "Passw0rd!");

        mockMvc.perform(post("/api/v1/auth/login")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "correct-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(success())
                .andExpect(jsonPath("$.data.mfaRequired").value(false))
                .andExpect(jsonPath("$.data.accessToken").exists())
                .andExpect(jsonPath("$.data.username").value(user.getUsername()));
    }

    @Test
    void login_withNoClientCredentials_isUnauthorized() throws Exception {
        LoginRequest request = new LoginRequest("whoever", "whatever");

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_withWrongClientSecret_isUnauthorized() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        User user = userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(client.getId())
                .withPasswordHash(passwordEncoder.encode("Passw0rd!"))
                .build());
        LoginRequest request = new LoginRequest(user.getUsername(), "Passw0rd!");

        mockMvc.perform(post("/api/v1/auth/login")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "wrong-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }
}

package com.internal.auth.feature.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.dto.RegisterRequest;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import static com.internal.auth.testsupport.ApiResponseAssertions.success;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Step 12A (RegistrationController slice). Happy path plus the HTTP Basic
 * client-credential enforcement RegistrationController's own class Javadoc
 * describes: an unrecognized/missing/wrong clientId+clientSecret is
 * rejected outright (401), it never auto-creates a client application.
 */
class RegistrationControllerIT extends IntegrationTestBase {

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
    void register_withValidRequestAndClientCredentials_createsTheUserAndReturns201() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        RegisterRequest request = new RegisterRequest("new_user_12a", "+23480000321", "new12a@user.com", "Passw0rd!", "Passw0rd!");

        mockMvc.perform(post("/api/v1/auth/register")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "correct-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(success())
                .andExpect(jsonPath("$.data.username").value("new_user_12a"));

        Optional<User> saved = userRepository.findByUsernameAndClientApplicationId("new_user_12a", client.getId());
        assertThat(saved).isPresent();
        assertThat(saved.get().getEmail()).isEqualTo("new12a@user.com");
    }

    @Test
    void register_withNoClientCredentials_isUnauthorized() throws Exception {
        RegisterRequest request = new RegisterRequest("nobody_12a", "+23480000322", "nobody12a@user.com", "Passw0rd!", "Passw0rd!");

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void register_withWrongClientSecret_isUnauthorized() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        RegisterRequest request = new RegisterRequest("nobody_12a_2", "+23480000323", "nobody12a2@user.com", "Passw0rd!", "Passw0rd!");

        mockMvc.perform(post("/api/v1/auth/register")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "wrong-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());

        assertThat(userRepository.findByUsernameAndClientApplicationId("nobody_12a_2", client.getId())).isEmpty();
    }
}

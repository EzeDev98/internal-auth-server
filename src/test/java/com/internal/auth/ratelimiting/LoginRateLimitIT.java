package com.internal.auth.ratelimiting;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.dto.request.LoginRequest;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.ResultActions;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import static com.internal.auth.testsupport.ApiResponseAssertions.message;
import static com.internal.auth.testsupport.ApiResponseAssertions.success;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Verifies the login rate limits. */
class LoginRateLimitIT extends IntegrationTestBase {

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

    private String freshFakeIp(int block) {
        return "10.15." + block + "." + (1 + (Math.abs(UUID.randomUUID().hashCode()) % 250));
    }

    private ResultActions attemptLogin(String remoteAddr, ClientApplication client, String clientSecret,
                                        String username, String password) throws Exception {
        LoginRequest request = new LoginRequest(username, password);
        return mockMvc.perform(post("/api/v1/auth/login")
                .with(req -> {
                    req.setRemoteAddr(remoteAddr);
                    return req;
                })
                .header("Authorization", basicAuthHeader(client.getClientId(), clientSecret))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));
    }

    @Test
    void accountLoginLimit_tripsIndependentlyOfIpLimit_andNeverBlocksADifferentAccount() throws Exception {
        String fakeIp = freshFakeIp(1);
        String clientSecret = "acct-limit-secret-15a";
        ClientApplication client = clientApplicationRepository.save(
                ClientApplicationTestDataBuilder.aClientApplication()
                        .withClientSecretHash(passwordEncoder.encode(clientSecret))
                        .build());

        String targetUsername = "acct_limit_target_" + UUID.randomUUID();
        String correctPassword = "CorrectPassw0rd!";
        userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(client.getId())
                .withUsername(targetUsername)
                .withPasswordHash(passwordEncoder.encode(correctPassword))
                .build());

        for (int i = 0; i < 5; i++) {
            attemptLogin(fakeIp, client, clientSecret, targetUsername, "wrong-password-" + i)
                    .andExpect(status().isUnauthorized());
        }

        attemptLogin(fakeIp, client, clientSecret, targetUsername, correctPassword)
                .andExpect(status().isTooManyRequests())
                .andExpect(message("Too many requests. Please try again later."));

        String otherUsername = "acct_limit_other_" + UUID.randomUUID();
        String otherPassword = "AnotherPassw0rd!";
        userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(client.getId())
                .withUsername(otherUsername)
                .withPasswordHash(passwordEncoder.encode(otherPassword))
                .build());

        attemptLogin(fakeIp, client, clientSecret, otherUsername, otherPassword)
                .andExpect(status().isOk())
                .andExpect(success());
    }

    @Test
    void ipLoginLimit_tripsOnItsOwn_evenWhenNoSingleAccountEverNearsItsOwnLimit() throws Exception {
        String fakeIp = freshFakeIp(2);
        String clientSecret = "ip-limit-secret-15a";
        ClientApplication client = clientApplicationRepository.save(
                ClientApplicationTestDataBuilder.aClientApplication()
                        .withClientSecretHash(passwordEncoder.encode(clientSecret))
                        .build());

        for (int i = 0; i < 10; i++) {
            attemptLogin(fakeIp, client, clientSecret, "ip_limit_user_" + i + "_" + UUID.randomUUID(), "whatever-password")
                    .andExpect(status().isUnauthorized());
        }

        attemptLogin(fakeIp, client, clientSecret, "ip_limit_user_10_" + UUID.randomUUID(), "whatever-password")
                .andExpect(status().isTooManyRequests())
                .andExpect(message("Too many requests. Please try again later."));
    }
}

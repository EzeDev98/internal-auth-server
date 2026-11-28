package com.internal.auth.ratelimiting;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.dockerjava.api.DockerClient;
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

import static com.internal.auth.testsupport.ApiResponseAssertions.success;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Verifies rate limiting fails closed when Redis is unavailable. */
class RedisOutageIT extends IntegrationTestBase {

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

    private String freshFakeIp() {
        return "10.30." + (1 + (Math.abs(UUID.randomUUID().hashCode()) % 250)) + "."
                + (1 + (Math.abs(UUID.randomUUID().hashCode() >> 8) % 250));
    }

    private ResultActions attemptLogin(String remoteAddr, ClientApplication client, String clientSecret,
                                        String username, String password) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/login")
                .with(req -> {
                    req.setRemoteAddr(remoteAddr);
                    return req;
                })
                .header("Authorization", basicAuthHeader(client.getClientId(), clientSecret))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new LoginRequest(username, password))));
    }

    @Test
    void loginRateLimiterFailsClosed_whenRedisIsUnreachable_evenWithCorrectCredentials() throws Exception {
        String fakeIp = freshFakeIp();
        String clientSecret = "redis-outage-secret-16c";
        ClientApplication client = clientApplicationRepository.save(
                ClientApplicationTestDataBuilder.aClientApplication()
                        .withClientSecretHash(passwordEncoder.encode(clientSecret))
                        .build());

        String username = "redis_outage_user_" + UUID.randomUUID();
        String correctPassword = "CorrectPassw0rd!";
        userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(client.getId())
                .withUsername(username)
                .withPasswordHash(passwordEncoder.encode(correctPassword))
                .build());

        attemptLogin(fakeIp, client, clientSecret, username, correctPassword)
                .andExpect(status().isOk())
                .andExpect(success());

        DockerClient dockerClient = REDIS.getDockerClient();
        String redisContainerId = REDIS.getContainerId();

        dockerClient.pauseContainerCmd(redisContainerId).exec();
        try {
            attemptLogin(fakeIp, client, clientSecret, username, correctPassword)
                    .andExpect(status().isInternalServerError());
        } finally {
            dockerClient.unpauseContainerCmd(redisContainerId).exec();
        }

        attemptLogin(fakeIp, client, clientSecret, username, correctPassword)
                .andExpect(status().isOk())
                .andExpect(success());
    }
}

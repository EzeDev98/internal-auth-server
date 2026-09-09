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

/**
 * Step 16C: with Redis genuinely unreachable mid-request, RateLimiterService#checkRateLimit
 * must fail CLOSED (reject the request) rather than fail OPEN (silently
 * let the request through as if the limiter had approved it). The
 * distinguishing test here isn't "does a request during the outage get a
 * non-200" - it's "does a request carrying otherwise-CORRECT credentials
 * still get rejected", since only that proves the failure genuinely
 * short-circuits business logic rather than merely coinciding with an
 * already-failing request.
 *
 * <p>Ground-truthed the mechanism: RateLimiterService#checkRateLimit has
 * no try/catch around redissonClient.getRateLimiter(...).tryAcquire() -
 * an unreachable Redis surfaces as an unchecked Redisson exception (e.g.
 * RedisTimeoutException, a RuntimeException with no @ResponseStatus),
 * which GlobalExceptionHandler#handleRuntimeException falls through to
 * #handleUnexpected for: a 500 with the generic
 * "An unexpected error occurred..." body. That 500 - not a 200 - IS the
 * fail-closed behavior this test locks in; LoginController never reaches
 * loginService.login() at all once checkRateLimit throws.
 *
 * <p>Pausing (not stopping) the shared singleton REDIS container - via
 * the raw Docker client, since Testcontainers exposes no
 * higher-level API for it - freezes it at the cgroup level without
 * tearing down the container, its mapped port, or IntegrationTestBase's
 * already-live RedissonClient connection pool, so un-pausing fully
 * restores the exact same state for every IT class that runs after this
 * one in this JVM fork (see IntegrationTestBase's Javadoc: the Postgres
 * and Redis containers are a shared singleton pair, not per-class). The
 * pause/unpause is wrapped in try/finally specifically so a failed
 * assertion here can never leave Redis paused for the rest of the suite.
 *
 * <p>Redisson's configured retry policy (RedissonConfig: timeout=3000ms,
 * retryAttempts=3, retryInterval=1500ms) means the outage call below can
 * take up to ~15s to actually throw - a paused container doesn't reset
 * the TCP connection the way a stopped one would, so Redisson has to
 * genuinely exhaust its own command-timeout retries rather than fail
 * fast on a connection error. That latency is the outage being
 * faithfully simulated, not test flakiness.
 */
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

        // Baseline: Redis is up, correct credentials succeed normally -
        // establishes that a 500 later in this test is caused by the
        // outage, not by some unrelated setup mistake.
        attemptLogin(fakeIp, client, clientSecret, username, correctPassword)
                .andExpect(status().isOk())
                .andExpect(success());

        DockerClient dockerClient = REDIS.getDockerClient();
        String redisContainerId = REDIS.getContainerId();

        dockerClient.pauseContainerCmd(redisContainerId).exec();
        try {
            // Same client, same user, same CORRECT password - if the
            // limiter failed open, this would still return 200. It must
            // not: the request has to be rejected before
            // LoginServiceImpl ever compares the password.
            attemptLogin(fakeIp, client, clientSecret, username, correctPassword)
                    .andExpect(status().isInternalServerError());
        } finally {
            dockerClient.unpauseContainerCmd(redisContainerId).exec();
        }

        // Recovery: once Redis is reachable again, the identical request
        // succeeds again - confirms this test leaves the shared
        // singleton container healthy for every IT class that runs
        // after it in this JVM fork.
        attemptLogin(fakeIp, client, clientSecret, username, correctPassword)
                .andExpect(status().isOk())
                .andExpect(success());
    }
}

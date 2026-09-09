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

/**
 * Step 15A: LoginController's account-scoped login limit
 * (AppConstant.MAX_LOGIN_ACCOUNT_REQUEST=5, keyed by client_application_id +
 * username) tested independently of its IP-scoped limit
 * (MAX_LOGIN_REQUEST=10, keyed by the caller's remote address) - both must
 * trip correctly on their own, and neither must interfere with the other.
 *
 * <p>Every test in this suite so far has shared one MockHttpServletRequest
 * remote address ("127.0.0.1", MockMvc's own default) across the whole IT
 * run, since IntegrationTestBase reuses one Testcontainers Redis singleton
 * for every test class in this JVM fork - fine for tests that never call
 * /auth/login enough to approach MAX_LOGIN_REQUEST=10, but this class's
 * whole point is to deliberately exhaust rate-limit buckets, so it can't
 * share that address without contaminating (or being contaminated by)
 * every other IT class's login calls.
 *
 * <p>Ground-truthed the fix: IntegrationTestBase runs
 * {@code @SpringBootTest(webEnvironment = DEFINED_PORT)} but MockMvc (via
 * {@code @AutoConfigureMockMvc}) still dispatches directly against the
 * DispatcherServlet in-process - it never actually goes through the real
 * embedded Tomcat connector (that connector exists only for tests that
 * open a real socket to it, e.g. ActuatorManagementPortIT's raw
 * HttpClient). So {@code server.forward-headers-strategy} and Tomcat's
 * RemoteIpValve - relevant to Step 15B, not here - are simply not in the
 * request path for MockMvc at all; a request's
 * {@code HttpServletRequest#getRemoteAddr()} is just whatever the
 * MockHttpServletRequest object reports, freely settable per-request via a
 * RequestPostProcessor with no dependency on any header or app property.
 * Each test below picks its own randomized, never-reused fake address for
 * exactly this reason - real isolation, not a fragile ordering assumption.
 */
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

        // AppConstant.MAX_LOGIN_ACCOUNT_REQUEST is 5 - burn through exactly
        // that many wrong-password attempts against this one (client,
        // username) pair. Each gets 401 (invalid credentials) - the
        // account bucket hasn't tripped yet, only real credential checks
        // are failing so far.
        for (int i = 0; i < 5; i++) {
            attemptLogin(fakeIp, client, clientSecret, targetUsername, "wrong-password-" + i)
                    .andExpect(status().isUnauthorized());
        }

        // The 6th attempt - even with the CORRECT password this time - is
        // rejected by the account rate limiter before loginService.login()
        // ever runs (LoginController#checkAccountRateLimit is called
        // first), proving this gates on attempt count against the
        // account, not on counting repeated failures specifically.
        attemptLogin(fakeIp, client, clientSecret, targetUsername, correctPassword)
                .andExpect(status().isTooManyRequests())
                .andExpect(message("Too many requests. Please try again later."));

        // A completely different username, same client, same (fake) IP -
        // and this IP has only made 6 requests so far, well under its own
        // 10-request limit - succeeds immediately. Proves the exhausted
        // account bucket above is genuinely scoped to that one username,
        // not to "this IP" or "this client" more broadly.
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

        // AppConstant.MAX_LOGIN_REQUEST is 10 - a fresh, never-before-used
        // username on every single call, so no individual account's own
        // 5-request limit is ever approached (each username is seen
        // exactly once); only the shared IP bucket accumulates.
        for (int i = 0; i < 10; i++) {
            attemptLogin(fakeIp, client, clientSecret, "ip_limit_user_" + i + "_" + UUID.randomUUID(), "whatever-password")
                    .andExpect(status().isUnauthorized());
        }

        attemptLogin(fakeIp, client, clientSecret, "ip_limit_user_10_" + UUID.randomUUID(), "whatever-password")
                .andExpect(status().isTooManyRequests())
                .andExpect(message("Too many requests. Please try again later."));
    }
}

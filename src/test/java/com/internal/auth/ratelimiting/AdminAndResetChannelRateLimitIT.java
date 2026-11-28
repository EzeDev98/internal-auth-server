package com.internal.auth.ratelimiting;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.dto.request.LoginRequest;
import com.internal.auth.feature.passwordreset.dto.request.CompletePasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.request.PasswordResetRequest;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.ResultActions;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import static com.internal.auth.testsupport.ApiResponseAssertions.message;
import static com.internal.auth.testsupport.ApiResponseAssertions.success;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Verifies rate limits on the admin, password reset and phone verification endpoints. */
class AdminAndResetChannelRateLimitIT extends IntegrationTestBase {

    private static final int PORT = 8085;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("server.port", () -> PORT);
        registry.add("password-reset.otp.resend-cooldown-seconds", () -> 1);
    }

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private ObjectMapper objectMapper;

    private String basicAuthHeader(String clientId, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private ClientApplication freshClient(String secret) {
        return clientApplicationRepository.save(
                ClientApplicationTestDataBuilder.aClientApplication()
                        .withClientSecretHash(passwordEncoder.encode(secret))
                        .build());
    }

    private String freshPhoneNumber() {
        return "070" + String.format("%08d", Math.abs(UUID.randomUUID().hashCode()) % 100_000_000);
    }

    private String freshFakeIp(int block) {
        return "10.20." + block + "." + (1 + (Math.abs(UUID.randomUUID().hashCode()) % 250));
    }

    private ResultActions requestOtp(ClientApplication client, String secret, String phone) throws Exception {
        return mockMvc.perform(post("/api/v1/password-reset/request")
                .header("Authorization", basicAuthHeader(client.getClientId(), secret))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new PasswordResetRequest(phone))));
    }

    private ResultActions verifyResetOtp(ClientApplication client, String secret, String phone) throws Exception {
        return mockMvc.perform(post("/api/v1/password-reset/verify-otp")
                .header("Authorization", basicAuthHeader(client.getClientId(), secret))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new VerifyOtpRequest(phone, "000000"))));
    }

    private ResultActions completeReset(String remoteAddr) throws Exception {
        return mockMvc.perform(post("/api/v1/password-reset/complete")
                .with(req -> {
                    req.setRemoteAddr(remoteAddr);
                    return req;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                        new CompletePasswordResetRequest(UUID.randomUUID().toString(), "ValidPassw0rd!", "ValidPassw0rd!"))));
    }

    private ResultActions verifyPhone(ClientApplication client, String secret, String phone) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/verify-phone")
                .header("Authorization", basicAuthHeader(client.getClientId(), secret))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new VerifyOtpRequest(phone, "000000"))));
    }

    private ResultActions adminLogin(String remoteAddr, String username, String password) throws Exception {
        return mockMvc.perform(post("/api/v1/admin/login")
                .with(req -> {
                    req.setRemoteAddr(remoteAddr);
                    return req;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new LoginRequest(username, password))));
    }

    @Test
    void passwordResetRequestLimit_tripsAtItsOwnThreshold_notItsOwnResendCooldown() throws Exception {
        ClientApplication client = freshClient("reset-request-secret-15d");
        String phone = freshPhoneNumber();

        for (int i = 0; i < 5; i++) {
            if (i > 0) {
                Thread.sleep(1100);
            }
            requestOtp(client, "reset-request-secret-15d", phone)
                    .andExpect(status().isOk())
                    .andExpect(success());
        }

        requestOtp(client, "reset-request-secret-15d", phone)
                .andExpect(status().isTooManyRequests())
                .andExpect(message("Too many requests. Please try again later."));
    }

    @Test
    void passwordResetVerifyOtpLimit_tripsAtItsOwnThreshold_independentOfRequestLimit() throws Exception {
        ClientApplication client = freshClient("reset-verify-secret-15d");
        String phone = freshPhoneNumber();

        for (int i = 0; i < 10; i++) {
            verifyResetOtp(client, "reset-verify-secret-15d", phone)
                    .andExpect(status().isBadRequest());
        }

        verifyResetOtp(client, "reset-verify-secret-15d", phone)
                .andExpect(status().isTooManyRequests())
                .andExpect(message("Too many requests. Please try again later."));
    }

    @Test
    void passwordResetCompleteLimit_tripsAtItsOwnThreshold_keyedByIpNotClientOrPhone() throws Exception {
        String fakeIp = freshFakeIp(1);

        for (int i = 0; i < 10; i++) {
            completeReset(fakeIp).andExpect(status().isBadRequest());
        }

        completeReset(fakeIp)
                .andExpect(status().isTooManyRequests())
                .andExpect(message("Too many requests. Please try again later."));
    }

    @Test
    void phoneVerificationVerifyLimit_isIsolatedFromPasswordResetVerifyLimit_evenWithTheSameClientAndPhone() throws Exception {
        ClientApplication client = freshClient("phone-verify-secret-15d");
        String phone = freshPhoneNumber();

        for (int i = 0; i < 10; i++) {
            verifyResetOtp(client, "phone-verify-secret-15d", phone)
                    .andExpect(status().isBadRequest());
        }
        verifyResetOtp(client, "phone-verify-secret-15d", phone)
                .andExpect(status().isTooManyRequests());

        verifyPhone(client, "phone-verify-secret-15d", phone)
                .andExpect(status().isBadRequest());

        for (int i = 0; i < 9; i++) {
            verifyPhone(client, "phone-verify-secret-15d", phone)
                    .andExpect(status().isBadRequest());
        }
        verifyPhone(client, "phone-verify-secret-15d", phone)
                .andExpect(status().isTooManyRequests())
                .andExpect(message("Too many requests. Please try again later."));
    }

    @Test
    void adminLoginLimit_isIsolatedFromRegularUserLoginLimit_evenFromTheSameIp() throws Exception {
        String fakeIp = freshFakeIp(2);
        ClientApplication client = freshClient("admin-vs-user-secret-15d");

        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .with(req -> {
                                req.setRemoteAddr(fakeIp);
                                return req;
                            })
                            .header("Authorization", basicAuthHeader(client.getClientId(), "admin-vs-user-secret-15d"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(new LoginRequest("nobody-" + i, "whatever"))))
                    .andExpect(status().isUnauthorized());
        }
        mockMvc.perform(post("/api/v1/auth/login")
                        .with(req -> {
                            req.setRemoteAddr(fakeIp);
                            return req;
                        })
                        .header("Authorization", basicAuthHeader(client.getClientId(), "admin-vs-user-secret-15d"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest("nobody-10", "whatever"))))
                .andExpect(status().isTooManyRequests());

        adminLogin(fakeIp, "no-such-admin", "whatever")
                .andExpect(status().isUnauthorized());
    }
}

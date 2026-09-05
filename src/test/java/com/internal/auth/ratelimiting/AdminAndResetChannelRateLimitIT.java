package com.internal.auth.ratelimiting;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.dto.LoginRequest;
import com.internal.auth.feature.identity.dto.VerifyLoginOtpRequest;
import com.internal.auth.feature.passwordreset.dto.CompletePasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.PasswordResetRequestDto;
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

/**
 * Step 15D: password-reset (/request, /verify-otp, /complete),
 * phone-verification (/verify-phone), and admin-login (/login,
 * /login/verify-otp) rate limits each trip on their own configured
 * threshold, and - the actual point of "own key prefixes" - exhausting
 * one never blocks another even when the underlying identity being
 * guessed (same client+phone, or same caller IP) is identical across
 * both.
 *
 * <p>Claims verified per AppConstant/PasswordResetController:
 * MAX_RESET_PASSWORD_REQUEST=5 ("ratelimit:password-reset-otp:phone:"),
 * MAX_VERIFY_OTP_REQUEST=10 (VERIFY_OTP_RATE_LIMIT_KEY_PREFIX),
 * MAX_COMPLETE_RESET_REQUEST=10 (COMPLETE_RESET_RATE_LIMIT_KEY_PREFIX,
 * IP-keyed, no client credentials needed), MAX_PHONE_VERIFICATION_VERIFY_REQUEST=10
 * (PHONE_VERIFICATION_VERIFY_RATE_LIMIT_KEY_PREFIX), and both admin-login
 * buckets (LOGIN_RATE_LIMIT_KEY_PREFIX / LOGIN_OTP_VERIFY_RATE_LIMIT_KEY_PREFIX,
 * each with an "admin:" segment appended ahead of the IP - see
 * AdminController) MAX=10 each.
 *
 * <p>Ground-truthed PasswordResetServiceImpl#requestOtp: user-enumeration
 * protection means /request always returns 200 with
 * AppConstant.GENERIC_REQUEST_MESSAGE regardless of whether the phone is
 * registered - no user setup needed for that endpoint. It also arms its
 * OWN resend-cooldown bucket (a mechanism entirely separate from the rate
 * limiter, see OtpResetEngine) on every call, which at the default 60s
 * would 429 on call 2 before the rate limiter's 5-request cap is ever
 * reached; password-reset.otp.resend-cooldown-seconds is overridden down
 * to 1s here so the loop can sleep past it and isolate the rate limiter's
 * own boundary specifically.
 *
 * <p>Follows the LoginRateLimitIT/ResendCooldownIT convention: dedicated
 * port (8085, distinct from 8080/8082/8083/8084) since @DynamicPropertySource
 * forces a separate cached ApplicationContext under webEnvironment=DEFINED_PORT,
 * and a fresh, never-reused fake IP or phone number per test to avoid
 * cross-test bucket collisions in the one Redis singleton this whole IT
 * run shares.
 */
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
                .content(objectMapper.writeValueAsString(new PasswordResetRequestDto(phone))));
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

    private ResultActions adminVerifyLoginOtp(String remoteAddr, String phone) throws Exception {
        return mockMvc.perform(post("/api/v1/admin/login/verify-otp")
                .with(req -> {
                    req.setRemoteAddr(remoteAddr);
                    return req;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new VerifyLoginOtpRequest(phone, "000000"))));
    }

    @Test
    void passwordResetRequestLimit_tripsAtItsOwnThreshold_notItsOwnResendCooldown() throws Exception {
        ClientApplication client = freshClient("reset-request-secret-15d");
        String phone = freshPhoneNumber();

        // MAX_RESET_PASSWORD_REQUEST=5. Sleeping past the (overridden, 1s)
        // per-request resend cooldown between calls means every 200 here
        // is genuinely the rate limiter's own counter advancing, not the
        // cooldown bucket blocking - enumeration protection means each
        // call succeeds with the same generic message regardless of
        // whether "phone" is a registered user.
        for (int i = 0; i < 5; i++) {
            if (i > 0) {
                Thread.sleep(1100);
            }
            requestOtp(client, "reset-request-secret-15d", phone)
                    .andExpect(status().isOk())
                    .andExpect(success());
        }

        // The 6th call is rejected by the rate limiter BEFORE the service
        // (and therefore its cooldown check) ever runs - fires
        // immediately, no sleep needed to prove that ordering.
        requestOtp(client, "reset-request-secret-15d", phone)
                .andExpect(status().isTooManyRequests())
                .andExpect(message("Too many requests. Please try again later."));
    }

    @Test
    void passwordResetVerifyOtpLimit_tripsAtItsOwnThreshold_independentOfRequestLimit() throws Exception {
        ClientApplication client = freshClient("reset-verify-secret-15d");
        String phone = freshPhoneNumber();

        // MAX_VERIFY_OTP_REQUEST=10 - no active OTP was ever requested for
        // this phone, so every pre-limit call fails validation with a
        // plain 400 (OtpInvalidException), never touching /request's
        // rate-limit key or cooldown bucket at all.
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

        // MAX_COMPLETE_RESET_REQUEST=10. No Authorization header, no
        // client, no phone - /complete resolves everything from the reset
        // token hash and rate-limits purely by caller IP.
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

        // Exhaust /password-reset/verify-otp's own MAX_VERIFY_OTP_REQUEST=10
        // bucket for this exact (client, phone) pair.
        for (int i = 0; i < 10; i++) {
            verifyResetOtp(client, "phone-verify-secret-15d", phone)
                    .andExpect(status().isBadRequest());
        }
        verifyResetOtp(client, "phone-verify-secret-15d", phone)
                .andExpect(status().isTooManyRequests());

        // /auth/verify-phone reuses the identical client+phone but a
        // different key prefix (PHONE_VERIFICATION_VERIFY_RATE_LIMIT_KEY_PREFIX
        // vs VERIFY_OTP_RATE_LIMIT_KEY_PREFIX) - proving isolation means
        // this must NOT be 429 despite the password-reset bucket above
        // being fully spent for the same identity.
        verifyPhone(client, "phone-verify-secret-15d", phone)
                .andExpect(status().isBadRequest());

        // And it has its own MAX_PHONE_VERIFICATION_VERIFY_REQUEST=10 cap,
        // which trips on its own too (already burned 1 above).
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

        // Exhaust the REGULAR user login IP bucket
        // (LOGIN_RATE_LIMIT_KEY_PREFIX + ip, MAX_LOGIN_REQUEST=10) via
        // LoginController - a real client, no matching user needed since
        // every attempt fails credential checks with 401 first.
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

        // AdminController#login uses LOGIN_RATE_LIMIT_KEY_PREFIX too, but
        // with an "admin:" segment ahead of the IP - from the SAME now-
        // exhausted IP, it must still get a normal 401 (unknown admin
        // credentials), not 429, proving the two buckets never share a key.
        adminLogin(fakeIp, "no-such-admin", "whatever")
                .andExpect(status().isUnauthorized());
    }

    @Test
    void adminLoginOtpVerifyLimit_isIsolatedFromAdminLoginPasswordLimit_evenFromTheSameIp() throws Exception {
        String fakeIp = freshFakeIp(3);

        // Exhaust admin /login's own MAX_LOGIN_REQUEST=10 bucket
        // (LOGIN_RATE_LIMIT_KEY_PREFIX + "admin:" + ip).
        for (int i = 0; i < 10; i++) {
            adminLogin(fakeIp, "no-such-admin-" + i, "whatever")
                    .andExpect(status().isUnauthorized());
        }
        adminLogin(fakeIp, "no-such-admin-10", "whatever")
                .andExpect(status().isTooManyRequests());

        // admin /login/verify-otp is a distinct bucket
        // (LOGIN_OTP_VERIFY_RATE_LIMIT_KEY_PREFIX + "admin:" + ip) - from
        // the same now-exhausted IP, it must still reach the service (400,
        // no active MFA OTP for this phone) rather than 429.
        adminVerifyLoginOtp(fakeIp, freshPhoneNumber())
                .andExpect(status().isBadRequest());
    }
}

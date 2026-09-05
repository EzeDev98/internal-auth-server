package com.internal.auth.ratelimiting;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Tag;

/**
 * Step 15C: resend endpoints (EmailVerificationController#resendActivation,
 * PhoneVerificationController#resendPhoneVerification) enforce their
 * configured cooldown, and the Retry-After header on the 429 they produce
 * matches it.
 *
 * <p>Both controllers delegate to the identical
 * OtpResetEngine#getCooldownBucket / rejectIfCoolingDown / startCooldown
 * sequence (see EmailVerificationServiceImpl#resendVerification /
 * PhoneVerificationServiceImpl#resendVerification), keyed by
 * "clientApplicationId:email" / "clientApplicationId:phoneNumber" - a fresh
 * (client, email-or-phone) pair per test avoids any cross-test cooldown
 * bucket collisions in the one Redis singleton this whole IT run shares.
 * GlobalExceptionHandler#handleOtpResendCooldown maps OtpResendCooldownException
 * to 429 with the Retry-After header set from
 * OtpResendCooldownException#getRetryAfterSeconds - always wrapped in
 * InternalAuthApiResponse regardless of which controller produced it, even
 * though the two controllers' own 200 success bodies are NOT symmetric:
 * EmailVerificationController wraps ("$.message" via InternalAuthApiResponse),
 * PhoneVerificationController returns the raw ActivationResponse directly
 * (also exposing "$.message", just not the same envelope - so the same
 * jsonPath happens to work for both, but "$.success" only exists on the
 * email endpoint's 200).
 *
 * <p>Ground-truthed OtpResetEngine#rejectIfCoolingDown:
 * {@code remainingSeconds = cooldownBucket.remainTimeToLive() / 1000} is
 * integer division against a real elapsed-time TTL, so an immediate
 * second call reports slightly LESS than the configured cooldown - the
 * Retry-After assertions below are deliberately a tolerant range
 * (cooldownSeconds - 1 .. cooldownSeconds), not brittle exact equality,
 * to account for that truncation rather than mask it.
 *
 * <p>Overrides both email-verification.resend-cooldown-seconds and
 * phone-verification.resend-cooldown-seconds (default 60, confirmed
 * unoverridden in application-test.properties) down to a short value via
 * @DynamicPropertySource so this test can also assert the cooldown
 * actually LIFTS at the configured time (not just that it 429s once) without
 * a 60-second sleep. Per the convention established for
 * LoginForwardedForTrustedProxyIT/LoginForwardedForUntrustedProxyIT
 * (Step 15B): any @DynamicPropertySource on an IntegrationTestBase subclass
 * forces Spring Test to cache a separate ApplicationContext, and since
 * webEnvironment=DEFINED_PORT means that context's embedded server really
 * binds server.port at context-refresh time, this class claims its own
 * dedicated port (8084, distinct from 8080/8082/8083) to avoid a real
 * bind conflict against the already-alive default shared context - even
 * though, like LoginRateLimitIT, this class only ever drives MockMvc and
 * never opens a real socket itself.
 */
@Tag("security-boundary")
class ResendCooldownIT extends IntegrationTestBase {

    private static final int PORT = 8084;
    private static final int COOLDOWN_SECONDS = 3;

    private static final String RESEND_ACTIVATION_PATH = "/api/v1/auth/resend-activation";
    private static final String RESEND_PHONE_VERIFICATION_PATH = "/api/v1/auth/resend-phone-verification";

    @DynamicPropertySource
    static void cooldownProperties(DynamicPropertyRegistry registry) {
        registry.add("server.port", () -> PORT);
        registry.add("email-verification.resend-cooldown-seconds", () -> COOLDOWN_SECONDS);
        registry.add("phone-verification.resend-cooldown-seconds", () -> COOLDOWN_SECONDS);
    }

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    private String basicAuthHeader(String clientId, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private ClientApplication newClientApplication(String secret) {
        return clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication()
                .withClientSecretHash(passwordEncoder.encode(secret))
                .build());
    }

    @Test
    void resendActivation_secondCallWithinCooldown_returns429WithRetryAfterMatchingConfiguredSeconds() throws Exception {
        String secret = "resend-email-secret-15c";
        ClientApplication client = newClientApplication(secret);
        String email = "resend_15c_" + UUID.randomUUID() + "@example.com";
        userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(client.getId())
                .withEmail(email)
                .withEmailVerified(false)
                .build());

        String auth = basicAuthHeader(client.getClientId(), secret);
        String requestBody = "{\"email\":\"" + email + "\"}";

        // First call: no cooldown bucket yet, succeeds and arms one.
        mockMvc.perform(post(RESEND_ACTIVATION_PATH)
                        .header(HttpHeaders.AUTHORIZATION, auth)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("A new verification link has been sent."));

        // Second call, immediately after: still cooling down - 429, wrapped
        // in the standard error envelope, Retry-After present and close to
        // (but, per the truncation caveat above, not necessarily exactly)
        // the configured 3 seconds.
        MvcResult secondCall = mockMvc.perform(post(RESEND_ACTIVATION_PATH)
                        .header(HttpHeaders.AUTHORIZATION, auth)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("Please wait before requesting another code."))
                .andExpect(header().exists(HttpHeaders.RETRY_AFTER))
                .andReturn();

        int retryAfter = Integer.parseInt(secondCall.getResponse().getHeader(HttpHeaders.RETRY_AFTER));
        assertThat(retryAfter)
                .as("Retry-After must reflect the configured %d-second cooldown, allowing for "
                        + "OtpResetEngine's integer-millisecond-truncation of the real remaining TTL", COOLDOWN_SECONDS)
                .isBetween(COOLDOWN_SECONDS - 1, COOLDOWN_SECONDS);

        // After actually waiting out the configured cooldown, a third call
        // succeeds again - proving the bucket really expires at the
        // configured duration rather than, say, never clearing or being
        // silently doubled.
        Thread.sleep((COOLDOWN_SECONDS + 1) * 1000L);
        mockMvc.perform(post(RESEND_ACTIVATION_PATH)
                        .header(HttpHeaders.AUTHORIZATION, auth)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void resendPhoneVerification_secondCallWithinCooldown_returns429WithRetryAfterMatchingConfiguredSeconds() throws Exception {
        String secret = "resend-phone-secret-15c";
        ClientApplication client = newClientApplication(secret);
        String phoneNumber = "0802" + String.valueOf(Math.abs(UUID.randomUUID().hashCode())).substring(0, 7);
        userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(client.getId())
                .withPhoneNumber(phoneNumber)
                .withPhoneVerified(false)
                .build());

        String auth = basicAuthHeader(client.getClientId(), secret);
        String requestBody = "{\"phoneNumber\":\"" + phoneNumber + "\"}";

        // First call: PhoneVerificationController's 200 body is the raw
        // ActivationResponse (not wrapped in InternalAuthApiResponse - see
        // class Javadoc), so only "$.message" is asserted here, not
        // "$.success".
        mockMvc.perform(post(RESEND_PHONE_VERIFICATION_PATH)
                        .header(HttpHeaders.AUTHORIZATION, auth)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("A new verification link has been sent."));

        // Second call: still cooling down. The 429 IS wrapped in
        // InternalAuthApiResponse regardless of the endpoint, since
        // GlobalExceptionHandler produces this response centrally, not
        // either controller's own success-path code.
        MvcResult secondCall = mockMvc.perform(post(RESEND_PHONE_VERIFICATION_PATH)
                        .header(HttpHeaders.AUTHORIZATION, auth)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("Please wait before requesting another code."))
                .andExpect(header().exists(HttpHeaders.RETRY_AFTER))
                .andReturn();

        int retryAfter = Integer.parseInt(secondCall.getResponse().getHeader(HttpHeaders.RETRY_AFTER));
        assertThat(retryAfter)
                .as("Retry-After must reflect the configured %d-second cooldown, allowing for "
                        + "OtpResetEngine's integer-millisecond-truncation of the real remaining TTL", COOLDOWN_SECONDS)
                .isBetween(COOLDOWN_SECONDS - 1, COOLDOWN_SECONDS);

        Thread.sleep((COOLDOWN_SECONDS + 1) * 1000L);
        mockMvc.perform(post(RESEND_PHONE_VERIFICATION_PATH)
                        .header(HttpHeaders.AUTHORIZATION, auth)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("A new verification link has been sent."));
    }
}

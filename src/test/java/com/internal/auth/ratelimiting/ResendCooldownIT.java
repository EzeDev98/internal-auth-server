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

/** Verifies the resend cooldown on verification endpoints. */
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

        mockMvc.perform(post(RESEND_ACTIVATION_PATH)
                        .header(HttpHeaders.AUTHORIZATION, auth)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("A new verification link has been sent."));

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

        mockMvc.perform(post(RESEND_PHONE_VERIFICATION_PATH)
                        .header(HttpHeaders.AUTHORIZATION, auth)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("A new verification link has been sent."));

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

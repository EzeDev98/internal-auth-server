package com.internal.auth.feature.passwordreset.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.common.reset.OtpResetEngine;
import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.passwordreset.dto.CompletePasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.PasswordResetRequestDto;
import com.internal.auth.feature.passwordreset.model.PasswordResetOtp;
import com.internal.auth.feature.passwordreset.repository.PasswordResetOtpRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.internal.auth.testsupport.ApiResponseAssertions.success;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Step 12A (PasswordResetController slice). /request and /verify-otp both
 * require the same HTTP Basic client-credential header (see the
 * controller's own class Javadoc); /complete deliberately doesn't - it
 * resolves everything from the reset token's own hash. /request's own raw
 * OTP is never retrievable from its response (app.otp.provider=logging in
 * the test profile only logs it - by design, the same enumeration-resistant
 * behavior production has), so the full verify-otp -> complete chain seeds
 * a known OTP directly via OtpResetEngine.populateNewOtp (the exact
 * production code path PasswordResetServiceImpl itself uses) rather than
 * trying to recover a real one from /request.
 */
class PasswordResetControllerIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordResetOtpRepository passwordResetOtpRepository;
    @Autowired
    private OtpResetEngine otpResetEngine;
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
    void requestOtp_withValidClientCredentials_succeeds() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(client.getId())
                .withPhoneNumber("+23480000801")
                .build());
        PasswordResetRequestDto request = new PasswordResetRequestDto("+23480000801");

        mockMvc.perform(post("/api/v1/password-reset/request")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "correct-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(success());
    }

    @Test
    void requestOtp_withNoClientCredentials_isUnauthorized() throws Exception {
        PasswordResetRequestDto request = new PasswordResetRequestDto("+23480000802");

        mockMvc.perform(post("/api/v1/password-reset/request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void requestOtp_withWrongClientSecret_isUnauthorized() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        PasswordResetRequestDto request = new PasswordResetRequestDto("+23480000803");

        mockMvc.perform(post("/api/v1/password-reset/request")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "wrong-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void verifyOtpThenComplete_withAValidOtpAndResetToken_changesThePassword() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        User user = userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(client.getId())
                .withPhoneNumber("+23480000804")
                .withPasswordHash(passwordEncoder.encode("OldPassw0rd!"))
                .build());

        String rawOtp = "654321";
        PasswordResetOtp otp = new PasswordResetOtp();
        otp.setUserId(user.getId());
        otp.setClientApplicationId(client.getId());
        otpResetEngine.populateNewOtp(otp, user.getPhoneNumber(), rawOtp, 5, 5);
        passwordResetOtpRepository.save(otp);

        VerifyOtpRequest verifyRequest = new VerifyOtpRequest(user.getPhoneNumber(), rawOtp);
        MvcResult verifyResult = mockMvc.perform(post("/api/v1/password-reset/verify-otp")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "correct-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(verifyRequest)))
                .andExpect(status().isOk())
                .andExpect(success())
                .andReturn();

        JsonNode body = objectMapper.readTree(verifyResult.getResponse().getContentAsString());
        String resetToken = body.path("data").path("resetToken").asText();
        assertThat(resetToken).isNotBlank();

        CompletePasswordResetRequest completeRequest =
                new CompletePasswordResetRequest(resetToken, "NewPassw0rd!", "NewPassw0rd!");

        mockMvc.perform(post("/api/v1/password-reset/complete")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(completeRequest)))
                .andExpect(status().isOk())
                .andExpect(success());

        User reloaded = userRepository.findById(user.getId()).orElseThrow();
        assertThat(passwordEncoder.matches("NewPassw0rd!", reloaded.getPassword())).isTrue();
    }
}

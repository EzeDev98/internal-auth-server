package com.internal.auth.feature.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.common.reset.OtpResetEngine;
import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.dto.request.ResendPhoneVerificationRequest;
import com.internal.auth.feature.identity.model.PhoneVerificationOtp;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.PhoneVerificationOtpRepository;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Step 12A (PhoneVerificationController slice). Both /verify-phone and
 * /resend-phone-verification require the same HTTP Basic client-credential
 * header (see the controller's own class Javadoc). The real OTP row for
 * the happy path is built with OtpResetEngine.populateNewOtp - the exact
 * production code path PhoneVerificationServiceImpl itself uses - so the
 * raw OTP submitted here really does have to match its stored hash.
 */
class PhoneVerificationControllerIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PhoneVerificationOtpRepository phoneVerificationOtpRepository;
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
    void verifyPhone_withAValidOtpAndClientCredentials_marksThePhoneVerified() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        User user = userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(client.getId())
                .withPhoneNumber("+23480000901")
                .withPhoneVerified(false)
                .build());

        String rawOtp = "123456";
        PhoneVerificationOtp otp = new PhoneVerificationOtp();
        otp.setUserId(user.getId());
        otp.setClientApplicationId(client.getId());
        otpResetEngine.populateNewOtp(otp, user.getPhoneNumber(), rawOtp, 10, 5);
        phoneVerificationOtpRepository.save(otp);

        VerifyOtpRequest request = new VerifyOtpRequest(user.getPhoneNumber(), rawOtp);

        mockMvc.perform(post("/api/v1/auth/verify-phone")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "correct-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        assertThat(userRepository.findById(user.getId()).orElseThrow().isPhoneVerified()).isTrue();
    }

    @Test
    void resendPhoneVerification_withValidClientCredentials_succeeds() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        ResendPhoneVerificationRequest request = new ResendPhoneVerificationRequest("+23480000902");

        mockMvc.perform(post("/api/v1/auth/resend-phone-verification")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "correct-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    void resendPhoneVerification_withNoClientCredentials_isUnauthorized() throws Exception {
        ResendPhoneVerificationRequest request = new ResendPhoneVerificationRequest("+23480000903");

        mockMvc.perform(post("/api/v1/auth/resend-phone-verification")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void resendPhoneVerification_withWrongClientSecret_isUnauthorized() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        ResendPhoneVerificationRequest request = new ResendPhoneVerificationRequest("+23480000904");

        mockMvc.perform(post("/api/v1/auth/resend-phone-verification")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "wrong-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }
}

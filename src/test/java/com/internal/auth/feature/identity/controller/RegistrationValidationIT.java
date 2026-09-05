package com.internal.auth.feature.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.dto.RegisterRequest;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.internal.auth.testsupport.ApiResponseAssertions.failure;
import static com.internal.auth.testsupport.ApiResponseAssertions.message;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Step 12C: validation-error paths against RegistrationController - chosen
 * over the other Step 12A-covered controllers since RegistrationServiceImpl
 * exercises the fullest validator chain (RegistrationValidator's
 * username/contact-info/phone/email rules, then ResetValidator's password
 * rule) in one call, in that exact order. Every case here supplies valid
 * HTTP Basic client credentials so the only thing under test is the
 * Step 5 exception shape (GlobalExceptionHandler -> InternalAuthApiResponse
 * envelope with success=false), never the separate 401 client-credential
 * path RegistrationControllerIT already covers.
 *
 * Malformed JSON is deliberately first: @RequestBody argument resolution
 * happens before RegistrationController#register's body ever runs, so
 * HttpMessageNotReadableException fires regardless of which validator rule
 * a well-formed body would have hit next.
 */
class RegistrationValidationIT extends IntegrationTestBase {

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

    private ClientApplication persistClientWithSecret(String plaintextSecret) {
        return clientApplicationRepository.save(
                ClientApplicationTestDataBuilder.aClientApplication()
                        .withClientSecretHash(passwordEncoder.encode(plaintextSecret))
                        .build());
    }

    @Test
    void malformedJsonBody_returnsBadRequestWithGenericMessage() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");

        mockMvc.perform(post("/api/v1/auth/register")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "correct-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ not-valid-json"))
                .andExpect(status().isBadRequest())
                .andExpect(failure())
                .andExpect(message("Malformed or missing request body"));
    }

    @Test
    void missingUsername_isRejectedWithBadRequest() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        RegisterRequest request = new RegisterRequest("", "+23480000341", "valid12c@user.com", "Passw0rd!", "Passw0rd!");

        mockMvc.perform(post("/api/v1/auth/register")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "correct-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(failure())
                .andExpect(message("Username is required"));
    }

    @Test
    void missingContactInfo_isRejectedWithBadRequest() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        RegisterRequest request = new RegisterRequest("valid_user_12c", null, null, "Passw0rd!", "Passw0rd!");

        mockMvc.perform(post("/api/v1/auth/register")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "correct-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(failure())
                .andExpect(message("At least one of phone number or email is required"));
    }

    @Test
    void invalidPhoneFormat_isRejectedWithBadRequest() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        RegisterRequest request = new RegisterRequest("valid_user_12c_2", "12345", null, "Passw0rd!", "Passw0rd!");

        mockMvc.perform(post("/api/v1/auth/register")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "correct-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(failure())
                .andExpect(message("Please enter a valid phone number"));
    }

    @Test
    void invalidEmailFormat_isRejectedWithBadRequest() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        RegisterRequest request = new RegisterRequest("valid_user_12c_3", null, "not-an-email", "Passw0rd!", "Passw0rd!");

        mockMvc.perform(post("/api/v1/auth/register")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "correct-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(failure())
                .andExpect(message("Please enter a valid email address"));
    }

    @Test
    void mismatchedPasswordConfirmation_isRejectedWithBadRequest() throws Exception {
        ClientApplication client = persistClientWithSecret("correct-secret");
        RegisterRequest request = new RegisterRequest("valid_user_12c_4", "+23480000342", null, "Passw0rd!", "Different1!");

        mockMvc.perform(post("/api/v1/auth/register")
                        .header("Authorization", basicAuthHeader(client.getClientId(), "correct-secret"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(failure())
                .andExpect(message("Passwords do not match"));
    }
}

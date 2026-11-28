package com.internal.auth.config.auth;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Integration tests for ClientApplicationRegisteredClientRepository. */
class ClientApplicationRegisteredClientRepositoryIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void clientCredentialsTokenIssuance_succeeds_withoutEverCallingRegisteredClientRepositorySave() throws Exception {
        String plaintextSecret = "diff-test-client-secret";
        ClientApplication client = clientApplicationRepository.save(
                ClientApplicationTestDataBuilder.aClientApplication()
                        .withClientSecretHash(passwordEncoder.encode(plaintextSecret))
                        .build());

        String basicAuth = "Basic " + Base64.getEncoder().encodeToString(
                (client.getClientId() + ":" + plaintextSecret).getBytes(StandardCharsets.UTF_8));

        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", basicAuth)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials")
                        .param("scope", "openid"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.token_type").value("Bearer"));
    }
}

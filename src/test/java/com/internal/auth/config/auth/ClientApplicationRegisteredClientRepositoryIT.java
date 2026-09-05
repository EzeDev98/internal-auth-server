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

/**
 * Step 11C (integration half). Drives a real client_credentials grant
 * through POST /oauth2/token - the actual Spring Authorization Server
 * machinery this app doesn't hand-roll (OAuth2ClientAuthenticationFilter,
 * OAuth2TokenEndpointFilter, OAuth2ClientCredentialsAuthenticationProvider)
 * - against a real persisted ClientApplication. That path only ever calls
 * RegisteredClientRepository#findByClientId to authenticate the caller and
 * OAuth2AuthorizationService#save (a different bean entirely, see
 * AuthorizationServerConfig#authorizationService) to persist the resulting
 * OAuth2Authorization; nothing in ordinary token issuance calls
 * RegisteredClientRepository#save. A 200 with an access_token proves that
 * held true here - ClientApplicationRegisteredClientRepositoryTest already
 * confirmed save() throws immediately if anything ever does call it, so a
 * 500 here (not a plausible outcome, but the point of this test) would
 * mean Spring Security's internals started calling it after some future
 * change.
 */
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

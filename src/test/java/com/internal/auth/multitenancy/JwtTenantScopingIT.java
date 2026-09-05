package com.internal.auth.multitenancy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.dto.LoginRequest;
import com.internal.auth.feature.identity.dto.SetMfaRequest;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import static com.internal.auth.testsupport.ApiResponseAssertions.success;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Tag;

/**
 * Step 14B: a JWT minted for tenant A is rejected or correctly scoped
 * against a tenant-B-scoped operation.
 *
 * <p>Grepped every production call site of AuthenticationHelper#getCurrentClientApplicationId
 * (the only claim a caller's own JWT carries that any operation scopes
 * itself by) - there are exactly two: JwtSessionTrackingFilter (already
 * covered end-to-end by Step 14A's MultiTenantUsernameCollisionIT) and
 * MfaSelfServiceController, covered here. Deliberately takes no username or
 * clientId parameter at all (see its own class Javadoc) - both are resolved
 * purely from the caller's own JWT - so there is no "target tenant B's
 * operation with tenant A's token" request to even construct; the only
 * meaningful boundary to prove is that this resolution never drifts onto a
 * same-named user in a different tenant, and that a token carrying no
 * client_application_id claim at all (a real client_credentials grant, per
 * this controller's own Javadoc) is rejected outright rather than falling
 * back to some ambiguous or unscoped lookup.
 */
@Tag("security-boundary")
class JwtTenantScopingIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private ObjectMapper objectMapper;

    private static final String TENANT_A_SECRET = "tenant-a-secret-14b";
    private static final String TENANT_B_SECRET = "tenant-b-secret-14b";
    private static final String TENANT_A_PASSWORD = "TenantAPassw0rd!";

    private String sharedUsername;
    private ClientApplication tenantA;
    private ClientApplication tenantB;
    private User userA;
    private User userB;

    @BeforeEach
    void seedTwoTenantsWithTheSameUsername() {
        sharedUsername = "collide_14b_" + UUID.randomUUID();

        tenantA = clientApplicationRepository.save(
                ClientApplicationTestDataBuilder.aClientApplication()
                        .withClientSecretHash(passwordEncoder.encode(TENANT_A_SECRET))
                        .build());
        tenantB = clientApplicationRepository.save(
                ClientApplicationTestDataBuilder.aClientApplication()
                        .withClientSecretHash(passwordEncoder.encode(TENANT_B_SECRET))
                        .build());

        userA = userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(tenantA.getId())
                .withUsername(sharedUsername)
                .withPasswordHash(passwordEncoder.encode(TENANT_A_PASSWORD))
                .build());
        // Tenant B's same-named user - mfaEnabled must stay false throughout,
        // proving tenant A's self-service call never touches it.
        userB = userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(tenantB.getId())
                .withUsername(sharedUsername)
                .build());
    }

    private String basicAuthHeader(String clientId, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void mfaSelfService_tenantAToken_onlyTogglesTenantAsUser_neverTenantBsSameNamedUser() throws Exception {
        LoginRequest loginRequest = new LoginRequest(sharedUsername, TENANT_A_PASSWORD);
        String loginBody = mockMvc.perform(post("/api/v1/auth/login")
                        .header("Authorization", basicAuthHeader(tenantA.getClientId(), TENANT_A_SECRET))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(success())
                .andReturn().getResponse().getContentAsString();
        String tokenA = objectMapper.readTree(loginBody).path("data").path("accessToken").asText();
        assertThat(tokenA).isNotBlank();

        SetMfaRequest enableMfa = new SetMfaRequest(true);
        mockMvc.perform(post("/api/v1/mfa/self")
                        .header("Authorization", "Bearer " + tokenA)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(enableMfa)))
                .andExpect(status().isOk());

        User reloadedA = userRepository.findById(userA.getId()).orElseThrow();
        assertThat(reloadedA.isMfaEnabled()).isTrue();

        User reloadedB = userRepository.findById(userB.getId()).orElseThrow();
        assertThat(reloadedB.isMfaEnabled()).isFalse();
    }

    @Test
    void mfaSelfService_clientCredentialsTokenWithNoTenantClaim_isRejected() throws Exception {
        // A real client_credentials grant for tenant A's own client - the
        // exact mechanism Step 11C's ClientApplicationRegisteredClientRepositoryIT
        // proved works against a real persisted ClientApplication. Its
        // resulting JWT's principal is the authenticated client itself, not
        // a local user, so AuthorizationServerConfig#jwtTokenCustomizer
        // never stamps a client_application_id claim onto it (see
        // MfaSelfServiceController's own class Javadoc).
        String tokenBody = mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", basicAuthHeader(tenantA.getClientId(), TENANT_A_SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials")
                        .param("scope", "openid"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode tokenJson = objectMapper.readTree(tokenBody);
        String clientCredentialsToken = tokenJson.path("access_token").asText();
        assertThat(clientCredentialsToken).isNotBlank();

        SetMfaRequest enableMfa = new SetMfaRequest(true);
        mockMvc.perform(post("/api/v1/mfa/self")
                        .header("Authorization", "Bearer " + clientCredentialsToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(enableMfa)))
                .andExpect(status().isForbidden());

        // Rejected before ever resolving a target user - neither tenant's
        // same-named user was touched.
        User reloadedA = userRepository.findById(userA.getId()).orElseThrow();
        assertThat(reloadedA.isMfaEnabled()).isFalse();
        User reloadedB = userRepository.findById(userB.getId()).orElseThrow();
        assertThat(reloadedB.isMfaEnabled()).isFalse();
    }
}

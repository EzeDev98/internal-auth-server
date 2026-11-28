package com.internal.auth.multitenancy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.common.crypto.TokenHasher;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.dto.request.LoginRequest;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.model.UserRole;
import com.internal.auth.feature.rbac.repository.RolesRepository;
import com.internal.auth.feature.rbac.repository.UserRolesRepository;
import com.internal.auth.feature.session.model.UserSession;
import com.internal.auth.feature.session.repository.UserSessionRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.TestTokenMinter;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import com.internal.auth.testsupport.builder.RoleTestDataBuilder;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static com.internal.auth.testsupport.ApiResponseAssertions.errorCode;
import static com.internal.auth.testsupport.ApiResponseAssertions.failure;
import static com.internal.auth.testsupport.ApiResponseAssertions.success;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Tag;

/** Verifies two tenants can register the same username. */
@Tag("security-boundary")
class MultiTenantUsernameCollisionIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RolesRepository rolesRepository;
    @Autowired
    private UserRolesRepository userRolesRepository;
    @Autowired
    private UserSessionRepository userSessionRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private TestTokenMinter testTokenMinter;
    @Autowired
    private TokenHasher tokenHasher;
    @Autowired
    private ObjectMapper objectMapper;

    private static final String TENANT_A_SECRET = "tenant-a-secret-14a";
    private static final String TENANT_B_SECRET = "tenant-b-secret-14a";
    private static final String TENANT_A_PASSWORD = "TenantAPassw0rd!";
    private static final String TENANT_B_PASSWORD = "TenantBPassw0rd!";

    private String sharedUsername;
    private ClientApplication tenantA;
    private ClientApplication tenantB;
    private User userA;
    private User userB;
    private String tenantAOnlyRoleName;

    @BeforeEach
    void seedTwoTenantsWithTheSameUsername() {
        sharedUsername = "collide_14a_" + UUID.randomUUID();

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
        userB = userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(tenantB.getId())
                .withUsername(sharedUsername)
                .withPasswordHash(passwordEncoder.encode(TENANT_B_PASSWORD))
                .build());

        Role role = rolesRepository.save(RoleTestDataBuilder.aRole().build());
        tenantAOnlyRoleName = role.getRoleName();
        UserRole mapping = new UserRole();
        mapping.setUser(userA);
        mapping.setRole(role);
        mapping.setCreatedAt(LocalDateTime.now());
        userRolesRepository.save(mapping);
    }

    private String basicAuthHeader(String clientId, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private String login(ClientApplication client, String clientSecret, String password) throws Exception {
        LoginRequest request = new LoginRequest(sharedUsername, password);
        String body = mockMvc.perform(post("/api/v1/auth/login")
                        .header("Authorization", basicAuthHeader(client.getClientId(), clientSecret))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(success())
                .andReturn().getResponse().getContentAsString();
        JsonNode data = objectMapper.readTree(body).path("data");
        String accessToken = data.path("accessToken").asText();
        assertThat(accessToken).isNotBlank();
        return accessToken;
    }

    @Test
    void login_sameUsernameAcrossTwoTenants_authenticatesTheCorrectAccountAndScopesRolesInTheToken() throws Exception {
        String tokenA = login(tenantA, TENANT_A_SECRET, TENANT_A_PASSWORD);
        String tokenB = login(tenantB, TENANT_B_SECRET, TENANT_B_PASSWORD);

        JWTClaimsSet claimsA = SignedJWT.parse(tokenA).getJWTClaimsSet();
        assertThat(claimsA.getSubject()).isEqualTo(sharedUsername);
        assertThat(((Number) claimsA.getClaim("client_application_id")).longValue()).isEqualTo(tenantA.getId());
        assertThat(claimsA.getStringListClaim("roles")).containsExactly(tenantAOnlyRoleName);

        JWTClaimsSet claimsB = SignedJWT.parse(tokenB).getJWTClaimsSet();
        assertThat(claimsB.getSubject()).isEqualTo(sharedUsername);
        assertThat(((Number) claimsB.getClaim("client_application_id")).longValue()).isEqualTo(tenantB.getId());
        assertThat(claimsB.getStringListClaim("roles")).isNull();
    }

    @Test
    void login_withTheOtherTenantsPassword_isRejected() throws Exception {
        LoginRequest crossedIntoA = new LoginRequest(sharedUsername, TENANT_B_PASSWORD);
        mockMvc.perform(post("/api/v1/auth/login")
                        .header("Authorization", basicAuthHeader(tenantA.getClientId(), TENANT_A_SECRET))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(crossedIntoA)))
                .andExpect(status().isUnauthorized());

        LoginRequest crossedIntoB = new LoginRequest(sharedUsername, TENANT_A_PASSWORD);
        mockMvc.perform(post("/api/v1/auth/login")
                        .header("Authorization", basicAuthHeader(tenantB.getClientId(), TENANT_B_SECRET))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(crossedIntoB)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void sessionTracking_sameUsernameAcrossTwoTenants_tracksASeparateSessionRowPerUser() throws Exception {
        String tokenA = login(tenantA, TENANT_A_SECRET, TENANT_A_PASSWORD);
        String tokenB = login(tenantB, TENANT_B_SECRET, TENANT_B_PASSWORD);

        mockMvc.perform(delete("/api/v1/session")
                        .header("Authorization", "Bearer " + tokenA))
                .andExpect(status().isOk())
                .andExpect(success());
        mockMvc.perform(delete("/api/v1/session")
                        .header("Authorization", "Bearer " + tokenB))
                .andExpect(status().isOk())
                .andExpect(success());

        UserSession sessionA = userSessionRepository.findByTokenHash(tokenHasher.sha256Hex(tokenA)).orElseThrow();
        UserSession sessionB = userSessionRepository.findByTokenHash(tokenHasher.sha256Hex(tokenB)).orElseThrow();

        assertThat(sessionA.getId()).isNotEqualTo(sessionB.getId());
        assertThat(sessionA.getUserId()).isEqualTo(userA.getId());
        assertThat(sessionB.getUserId()).isEqualTo(userB.getId());
        assertThat(sessionA.isActive()).isFalse();
        assertThat(sessionB.isActive()).isFalse();
    }

    @Test
    void rbacAdminEndpoints_byCollidingUsername_failClosedInsteadOfMergingAcrossTenants() throws Exception {
        ClientApplication adminHomeClient = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        String adminToken = testTokenMinter.mintAccessToken(adminHomeClient.getId(), "admin_14a", List.of("create-admin"));

        mockMvc.perform(get("/api/v1/users/{username}/roles", sharedUsername)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isConflict())
                .andExpect(failure())
                .andExpect(errorCode("12007"));

        mockMvc.perform(get("/api/v1/users/{username}/permission-groups", sharedUsername)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isConflict())
                .andExpect(failure())
                .andExpect(errorCode("12007"));

        String tokenA = login(tenantA, TENANT_A_SECRET, TENANT_A_PASSWORD);
        mockMvc.perform(get("/api/v1/users/{username}/permission-groups", sharedUsername)
                        .header("Authorization", "Bearer " + tokenA))
                .andExpect(status().isConflict())
                .andExpect(failure())
                .andExpect(errorCode("12007"));
    }
}

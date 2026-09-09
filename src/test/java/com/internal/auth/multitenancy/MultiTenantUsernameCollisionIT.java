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

/**
 * Step 14A: two tenants (client applications) register the exact same
 * username. The multi-tenant redesign's whole premise is that this is
 * legal - username is only unique per client_application_id (see User's
 * class Javadoc, V8) - so login, JWT role-scoping, RBAC's admin-facing
 * username lookups, and JwtSessionTrackingFilter's session bookkeeping
 * must all still resolve to the correct one of the two users and never
 * blend or leak into the other, even though a bare username string alone
 * can no longer tell them apart.
 *
 * <p>Ground-truthed against three already-hardened code paths (audit
 * findings 1-3, each with its own "Step 2/3" Javadoc in the production
 * classes) plus two gaps found and fixed this step, with the user's
 * explicit go-ahead each time:
 * <ul>
 *   <li>LoginServiceImpl#login / #mintAccessToken - findByUsernameAndClientApplicationId
 *       resolves the login, findRolesByUserId (not findRolesByUsername)
 *       scopes the "roles" JWT claim to the specific user who logged in.</li>
 *   <li>EntityUtilityService#findUserRoles / #findUserPermissionGroups (this
 *       step's fix) - previously queried by bare username with no tenant
 *       scoping at all (findRolesByUsername / findPermissionGroupsByUsername),
 *       silently merging both tenants' data under one admin-facing response.
 *       Now routes through getUser(username)'s existing fail-closed guard
 *       (409 AMBIGUOUS_USERNAME on collision) before resolving by user id -
 *       the same guard UserRoleServiceImpl's assign/unassign paths already
 *       relied on. Note this means a legitimate self-access caller (Step
 *       13C's fetchUserPermissionGroups path) also gets 409 once a same-
 *       username namesake exists in another tenant, rather than 200 with
 *       just their own groups - a deliberate fail-closed trade-off, since
 *       these RBAC endpoints carry no clientId parameter to disambiguate
 *       by design (RBAC is tenant-agnostic - see Step 14C), so there is no
 *       information available here to safely narrow an admin's lookup
 *       instead. It's tested explicitly below rather than left to be
 *       discovered as a surprise.</li>
 *   <li>JwtSessionTrackingFilter#trackSessionIfNeeded (this step's fix) -
 *       the short-circuit "already tracked recently" cache fell back to a
 *       bare username key whenever a token carried no "sid" claim, which
 *       is every self-issued local-login token - so two same-username
 *       tenants' users shared one cache entry and whichever one's request
 *       landed second within the cache TTL had its session tracking
 *       silently skipped. Now prefixed with client_application_id when the
 *       token carries that claim. Exercised below via DELETE /session
 *       (LogoutControl) rather than the RBAC endpoints above, since that
 *       path never looks anything up by username at all - it resolves
 *       purely from the caller's own bearer token hash - so it isn't
 *       entangled with the getUser(username) fail-closed behavior being
 *       tested separately.</li>
 * </ul>
 *
 * <p>Role name and username are both randomized per test method (not a
 * shared static constant) - IntegrationTestBase's Postgres is a reused
 * singleton across the whole IT run with no per-test rollback, and Role's
 * roleName has a global unique constraint, so a fixed literal would collide
 * with itself on the second @Test method in this class.
 */
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

        // Assigned to tenant A's user only - proves role lookup doesn't leak
        // into tenant B's same-named user's JWT.
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
        // Tenant B's same-named user has no roles assigned at all - the
        // customizer only adds a "roles" claim when authorities are
        // non-empty (see AuthorizationServerConfig#jwtTokenCustomizer), so
        // tenant A's role must not have leaked in as some kind of fallback.
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

        // DELETE /session never looks anything up by username - it resolves
        // purely from TokenHasher#sha256Hex(callerToken) - so it exercises
        // JwtSessionTrackingFilter (which runs first and creates the row)
        // without touching the RBAC ambiguous-username guard tested
        // separately below. Called back-to-back on purpose: the whole point
        // of this step's cache-key fix is that these two same-username
        // requests, arriving within the tracking filter's own short-circuit
        // cache TTL, must not collide with each other.
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
        // Both were successfully found and closed by the logout call above -
        // if the cache-key bug this step fixed had resurfaced, tokenB's
        // session row would never have been created in the first place and
        // the second DELETE /session call would have come back as a
        // 200-with-embedded-400 "No active session found" instead.
        assertThat(sessionA.isActive()).isFalse();
        assertThat(sessionB.isActive()).isFalse();
    }

    @Test
    void rbacAdminEndpoints_byCollidingUsername_failClosedInsteadOfMergingAcrossTenants() throws Exception {
        // A throwaway client application just to mint an admin-role token
        // from - unrelated to tenantA/tenantB above.
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

        // Even tenant A's own user, asking for their own groups, is refused
        // once a same-username namesake exists in another tenant - a
        // deliberate fail-closed trade-off (see class Javadoc): these
        // endpoints have no clientId parameter to disambiguate by, so
        // getUser(username)'s guard can't tell "the caller's own account"
        // apart from "some other tenant's row with the same name" and
        // refuses to guess either way.
        String tokenA = login(tenantA, TENANT_A_SECRET, TENANT_A_PASSWORD);
        mockMvc.perform(get("/api/v1/users/{username}/permission-groups", sharedUsername)
                        .header("Authorization", "Bearer " + tokenA))
                .andExpect(status().isConflict())
                .andExpect(failure())
                .andExpect(errorCode("12007"));
    }
}

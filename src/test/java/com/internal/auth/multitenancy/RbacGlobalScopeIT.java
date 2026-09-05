package com.internal.auth.multitenancy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.dto.LoginRequest;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.rbac.dto.AssignRoleRequest;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.repository.RolesRepository;
import com.internal.auth.feature.rbac.repository.UserRolesRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.TestTokenMinter;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import com.internal.auth.testsupport.builder.RoleTestDataBuilder;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static com.internal.auth.testsupport.ApiResponseAssertions.success;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Tag;

/**
 * Step 14C: locks in the deliberate product decision that RBAC (roles and
 * permission groups) stays global across tenants, so a future "fix" doesn't
 * reintroduce per-tenant scoping by accident.
 *
 * <p>Ground-truthed three separate pieces of evidence for this, from
 * strongest to weakest:
 * <ol>
 *   <li>V20__role_group_name_uniqueness.sql adds {@code uk_roles_role_name
 *       UNIQUE (role_name)} - a plain, non-composite unique constraint with
 *       no client_application_id in it at all (contrast with V8's
 *       {@code uk_users_client_username UNIQUE (client_application_id,
 *       username)} for User, which very much is per-tenant). Enforced by
 *       Postgres itself, not just application code - the strongest possible
 *       guarantee that two tenants can never each get their own
 *       identically-named "manager" role.</li>
 *   <li>The real admin RBAC API (PermissionController, via
 *       UserRoleServiceImpl) assigns and unassigns one shared Role row to
 *       users in any tenant with no client-scoping check anywhere in that
 *       path - proven end-to-end below rather than just at the schema
 *       level.</li>
 *   <li>Role#clientApplication and PermissionGroup#clientApplication (both
 *       added by the main build's own Step 13B, per their class Javadocs)
 *       are optional FK columns explicitly documented as "data model only
 *       ... deliberately not enforced by any repository/service/controller
 *       yet". Today every row leaves this null, but nothing stops a row
 *       from having it set - this class's last test populates it directly
 *       and proves it still has zero effect on assignability or on a real
 *       login's "roles" JWT claim, so this dormant column can't silently
 *       start scoping anything without this test failing first.</li>
 * </ol>
 */
@Tag("security-boundary")
class RbacGlobalScopeIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RolesRepository rolesRepository;
    @Autowired
    private UserRolesRepository userRolesRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private TestTokenMinter testTokenMinter;
    @Autowired
    private ObjectMapper objectMapper;

    private String adminToken(ClientApplication homeClient) {
        return testTokenMinter.mintAccessToken(homeClient.getId(), "admin_14c", List.of("create-admin"));
    }

    private ClientApplication newTenant() {
        return clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
    }

    @Test
    void roleName_hasAGlobalUniqueConstraint_notScopedPerTenant() {
        String sharedRoleName = "shared_role_14c_" + UUID.randomUUID();
        rolesRepository.save(RoleTestDataBuilder.aRole().withRoleName(sharedRoleName).build());

        Role duplicate = RoleTestDataBuilder.aRole().withRoleName(sharedRoleName).build();

        // No client_application_id column exists on this constraint at all
        // (see class Javadoc) - a second row with the same name is rejected
        // outright by Postgres, regardless of which tenant either "belongs"
        // to conceptually. If roles were ever made per-tenant, this exact
        // insert (same name, would-be-different tenant) is precisely the
        // one that should start succeeding - so this test is the tripwire
        // for that change too.
        assertThatThrownBy(() -> rolesRepository.saveAndFlush(duplicate))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void sameRole_assignableToUsersInDifferentTenants_independently() throws Exception {
        ClientApplication tenantA = newTenant();
        ClientApplication tenantB = newTenant();
        User userA = userRepository.save(UserTestDataBuilder.aUser().withClientApplicationId(tenantA.getId()).build());
        User userB = userRepository.save(UserTestDataBuilder.aUser().withClientApplicationId(tenantB.getId()).build());
        Role sharedRole = rolesRepository.save(RoleTestDataBuilder.aRole().build());
        String admin = adminToken(newTenant());

        AssignRoleRequest assignRequest = new AssignRoleRequest(sharedRole.getRoleName());

        // The exact same Role row, assigned to two users in two different
        // tenants - not two per-tenant copies of it.
        mockMvc.perform(post("/api/v1/users/{username}/roles", userA.getUsername())
                        .header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(assignRequest)))
                .andExpect(status().isCreated())
                .andExpect(success());
        mockMvc.perform(post("/api/v1/users/{username}/roles", userB.getUsername())
                        .header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(assignRequest)))
                .andExpect(status().isCreated())
                .andExpect(success());

        assertThat(userRolesRepository.findRolesByUserId(userA.getId()))
                .extracting(Role::getRoleName).contains(sharedRole.getRoleName());
        assertThat(userRolesRepository.findRolesByUserId(userB.getId()))
                .extracting(Role::getRoleName).contains(sharedRole.getRoleName());

        // Removing it from tenant A's user is purely a per-(user, role)
        // mapping change - tenant B's user keeps it. If assignment were
        // ever made tenant-aware, an unassign accidentally cascading across
        // tenants sharing a role is exactly the regression this guards.
        mockMvc.perform(delete("/api/v1/users/{username}/roles/{roleName}", userA.getUsername(), sharedRole.getRoleName())
                        .header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk())
                .andExpect(success());

        assertThat(userRolesRepository.findRolesByUserId(userA.getId()))
                .extracting(Role::getRoleName).doesNotContain(sharedRole.getRoleName());
        assertThat(userRolesRepository.findRolesByUserId(userB.getId()))
                .extracting(Role::getRoleName).contains(sharedRole.getRoleName());
    }

    @Test
    void roleWithItsDormantClientApplicationColumnSet_stillAssignableAndUsableAcrossAnyTenant() throws Exception {
        ClientApplication roleHomeTenant = newTenant();
        String otherTenantSecret = "other-tenant-secret-14c";
        ClientApplication otherTenant = clientApplicationRepository.save(
                ClientApplicationTestDataBuilder.aClientApplication()
                        .withClientSecretHash(passwordEncoder.encode(otherTenantSecret))
                        .build());

        // Directly populate the dormant, "not enforced by anything yet"
        // clientApplication column - simulating what a future change might
        // start writing, without this test also depending on that change
        // existing yet.
        Role role = RoleTestDataBuilder.aRole().build();
        role.setClientApplication(roleHomeTenant);
        role = rolesRepository.save(role);

        String targetPassword = "OtherTenantPassw0rd!";
        User targetUser = userRepository.save(UserTestDataBuilder.aUser()
                .withClientApplicationId(otherTenant.getId())
                .withPasswordHash(passwordEncoder.encode(targetPassword))
                .build());

        String admin = adminToken(newTenant());
        AssignRoleRequest assignRequest = new AssignRoleRequest(role.getRoleName());

        // Assignment succeeds even though the role's own dormant column
        // points at a completely different tenant than the target user's.
        mockMvc.perform(post("/api/v1/users/{username}/roles", targetUser.getUsername())
                        .header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(assignRequest)))
                .andExpect(status().isCreated())
                .andExpect(success());

        // And it's fully usable, not just recorded: a real login (not a
        // TestTokenMinter-shortcut token) for the target user carries it in
        // the JWT's "roles" claim, proving LoginServiceImpl#mintAccessToken's
        // findRolesByUserId lookup - the actual authorization-facing path -
        // never consults this dormant column either.
        LoginRequest loginRequest = new LoginRequest(targetUser.getUsername(), targetPassword);
        String loginBody = mockMvc.perform(post("/api/v1/auth/login")
                        .header("Authorization", basicAuthHeader(otherTenant.getClientId(), otherTenantSecret))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(success())
                .andReturn().getResponse().getContentAsString();
        String accessToken = objectMapper.readTree(loginBody).path("data").path("accessToken").asText();

        assertThat(SignedJWT.parse(accessToken).getJWTClaimsSet().getStringListClaim("roles"))
                .contains(role.getRoleName());
    }

    private String basicAuthHeader(String clientId, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }
}

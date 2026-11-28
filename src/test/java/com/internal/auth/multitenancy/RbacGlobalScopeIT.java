package com.internal.auth.multitenancy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.dto.request.LoginRequest;
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

/** Verifies roles and permission groups are shared across tenants. */
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

        mockMvc.perform(post("/api/v1/users/{username}/roles", targetUser.getUsername())
                        .header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(assignRequest)))
                .andExpect(status().isCreated())
                .andExpect(success());

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

package com.internal.auth.feature.rbac.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Tag;

/**
 * Step 13B: POST /service/users/{username}/roles's own fail-closed
 * app.service-role-assignment.allowed-roles gate (Stage 1 assessment,
 * "Immediate Next Steps" #3 - see PermissionController's own class Javadoc
 * and constructor: this endpoint used to let any caller holding the admin
 * authority grant ANY role, including an admin-tier one, to any user; now
 * nothing is assignable unless an operator explicitly lists it).
 *
 * Deliberately does NOT override app.service-role-assignment.allowed-roles
 * (no @DynamicPropertySource here, unlike PermissionControllerAdminHappyPathIT) -
 * this class exercises the real production default straight from
 * application.properties (empty), so "even a genuinely admin-authenticated,
 * otherwise-valid request is rejected" is proven against the actual shipped
 * configuration, not a property this test class introduced. The caller here
 * carries a real create-admin token (passes @PreAuthorize(Roles.HAS_ADMIN)
 * cleanly), so the 403 below can only come from the allow-list check inside
 * the method body itself - there's nothing else left in the chain that
 * could produce it for an admin caller.
 *
 * The allow-listed success case (an operator-configured role IS permitted)
 * is already covered by PermissionControllerAdminHappyPathIT's
 * assignRoleToUserForServiceToService test (Step 13A), which sets
 * app.service-role-assignment.allowed-roles via its own
 * @DynamicPropertySource - not repeated here as a separate test class/
 * Spring context, since a single @DynamicPropertySource value is fixed for
 * a whole test class and can't represent both "empty" and "allow-listed"
 * in one context.
 */
@Tag("security-boundary")
class ServiceRoleAssignmentAllowListIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RolesRepository rolesRepository;
    @Autowired
    private UserRolesRepository userRolesRepository;
    @Autowired
    private TestTokenMinter testTokenMinter;
    @Autowired
    private ObjectMapper objectMapper;

    private ClientApplication client;
    private String adminToken;

    @BeforeEach
    void mintAdminTokenAndClient() {
        client = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        adminToken = testTokenMinter.mintAccessToken(client.getId(), "admin_13b", List.of("create-admin"));
    }

    @Test
    void defaultEmptyAllowList_rejectsEveryRole_evenForAnAdminCaller() throws Exception {
        Role role = rolesRepository.save(RoleTestDataBuilder.aRole().build());
        User user = userRepository.save(UserTestDataBuilder.aUser().withClientApplicationId(client.getId()).build());
        AssignRoleRequest request = new AssignRoleRequest(role.getRoleName());

        mockMvc.perform(post("/api/v1/service/users/{username}/roles", user.getUsername())
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());

        assertThat(userRolesRepository.existsByUsernameAndRoleName(user.getUsername(), role.getRoleName())).isFalse();
    }
}

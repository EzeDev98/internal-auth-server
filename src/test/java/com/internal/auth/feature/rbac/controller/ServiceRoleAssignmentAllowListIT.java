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

/** Verifies the service role assignment allow-list. */
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

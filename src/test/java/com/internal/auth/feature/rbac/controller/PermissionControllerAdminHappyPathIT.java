package com.internal.auth.feature.rbac.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.rbac.dto.AddUserToGroupRequest;
import com.internal.auth.feature.rbac.dto.AddUserToSubGroupRequest;
import com.internal.auth.feature.rbac.dto.AddUserToSubGroupsRequest;
import com.internal.auth.feature.rbac.dto.AssignRoleRequest;
import com.internal.auth.feature.rbac.dto.AssignRoleToGroupRequest;
import com.internal.auth.feature.rbac.dto.AssignRoleToSubGroupRequest;
import com.internal.auth.feature.rbac.dto.GroupRequest;
import com.internal.auth.feature.rbac.dto.RolesRequest;
import com.internal.auth.feature.rbac.dto.SubGroupRequest;
import com.internal.auth.feature.rbac.model.PermissionGroup;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.model.RolePermissionGroupMapping;
import com.internal.auth.feature.rbac.model.SubPermissionGroup;
import com.internal.auth.feature.rbac.model.UserPermissionGroup;
import com.internal.auth.feature.rbac.model.UserRole;
import com.internal.auth.feature.rbac.repository.PermissionGroupsRepository;
import com.internal.auth.feature.rbac.repository.RolePermissionGroupMappingRepository;
import com.internal.auth.feature.rbac.repository.RolesRepository;
import com.internal.auth.feature.rbac.repository.SubPermissionGroupRepository;
import com.internal.auth.feature.rbac.repository.UserPermissionGroupRepository;
import com.internal.auth.feature.rbac.repository.UserRolesRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.TestTokenMinter;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import com.internal.auth.testsupport.builder.PermissionGroupTestDataBuilder;
import com.internal.auth.testsupport.builder.RoleTestDataBuilder;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static com.internal.auth.testsupport.ApiResponseAssertions.success;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Tag;

/** Integration tests for PermissionController with an admin token. */
@Tag("security-boundary")
class PermissionControllerAdminHappyPathIT extends IntegrationTestBase {

    private static final String SERVICE_ASSIGNABLE_ROLE = "svc_role_" + UUID.randomUUID();

    @DynamicPropertySource
    static void allowServiceRoleAssignment(DynamicPropertyRegistry registry) {
        registry.add("app.service-role-assignment.allowed-roles", () -> SERVICE_ASSIGNABLE_ROLE);
    }

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RolesRepository rolesRepository;
    @Autowired
    private PermissionGroupsRepository permissionGroupsRepository;
    @Autowired
    private SubPermissionGroupRepository subPermissionGroupRepository;
    @Autowired
    private RolePermissionGroupMappingRepository rolePermissionGroupMappingRepository;
    @Autowired
    private UserRolesRepository userRolesRepository;
    @Autowired
    private UserPermissionGroupRepository userPermissionGroupRepository;
    @Autowired
    private TestTokenMinter testTokenMinter;
    @Autowired
    private ObjectMapper objectMapper;

    private ClientApplication client;
    private String adminToken;

    @BeforeEach
    void mintAdminTokenAndClient() {
        client = clientApplicationRepository.save(ClientApplicationTestDataBuilder.aClientApplication().build());
        adminToken = testTokenMinter.mintAccessToken(client.getId(), "admin_13a", List.of("create-admin"));
    }

    private User persistUser() {
        return userRepository.save(UserTestDataBuilder.aUser().withClientApplicationId(client.getId()).build());
    }

    private SubPermissionGroup persistSubGroup(PermissionGroup parent) {
        SubPermissionGroup subGroup = new SubPermissionGroup();
        subGroup.setGroupName("test_subgroup_" + UUID.randomUUID());
        subGroup.setDescription("Created by PermissionControllerAdminHappyPathIT");
        subGroup.setParentGroup(parent);
        subGroup.setCreatedAt(LocalDateTime.now());
        return subPermissionGroupRepository.save(subGroup);
    }

    @Test
    void createRole_withAdminToken_returns201() throws Exception {
        String roleName = "role_13a_" + UUID.randomUUID();
        RolesRequest request = new RolesRequest(roleName, "Created by 13A");

        mockMvc.perform(post("/api/v1/roles")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(success());

        assertThat(rolesRepository.existsByRoleName(roleName)).isTrue();
    }

    @Test
    void createSuperGroup_withAdminToken_returns201() throws Exception {
        String groupName = "group_13a_" + UUID.randomUUID();
        GroupRequest request = new GroupRequest(groupName, "Created by 13A");

        mockMvc.perform(post("/api/v1/groups")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(success());

        assertThat(permissionGroupsRepository.existsByGroupName(groupName)).isTrue();
    }

    @Test
    void createSubGroup_withAdminToken_returns201() throws Exception {
        PermissionGroup parent = permissionGroupsRepository.save(PermissionGroupTestDataBuilder.aPermissionGroup().build());
        String subGroupName = "subgroup_13a_" + UUID.randomUUID();
        SubGroupRequest request = new SubGroupRequest(subGroupName, "Created by 13A");

        mockMvc.perform(post("/api/v1/groups/{parentGroupName}/subgroups", parent.getGroupName())
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(success());

        assertThat(subPermissionGroupRepository.existsByGroupName(subGroupName)).isTrue();
    }

    @Test
    void assignRoleToUserForServiceToService_withAnAllowListedRole_returns201() throws Exception {
        rolesRepository.save(RoleTestDataBuilder.aRole().withRoleName(SERVICE_ASSIGNABLE_ROLE).build());
        User user = persistUser();
        AssignRoleRequest request = new AssignRoleRequest(SERVICE_ASSIGNABLE_ROLE);

        mockMvc.perform(post("/api/v1/service/users/{username}/roles", user.getUsername())
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(success());

        assertThat(userRolesRepository.existsByUsernameAndRoleName(user.getUsername(), SERVICE_ASSIGNABLE_ROLE)).isTrue();
    }

    @Test
    void assignRoleToUser_withAdminToken_returns201() throws Exception {
        Role role = rolesRepository.save(RoleTestDataBuilder.aRole().build());
        User user = persistUser();
        AssignRoleRequest request = new AssignRoleRequest(role.getRoleName());

        mockMvc.perform(post("/api/v1/users/{username}/roles", user.getUsername())
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(success());

        assertThat(userRolesRepository.existsByUsernameAndRoleName(user.getUsername(), role.getRoleName())).isTrue();
    }

    @Test
    void assignRoleToGroup_withAdminToken_returns201() throws Exception {
        Role role = rolesRepository.save(RoleTestDataBuilder.aRole().build());
        PermissionGroup group = permissionGroupsRepository.save(PermissionGroupTestDataBuilder.aPermissionGroup().build());
        AssignRoleToGroupRequest request = new AssignRoleToGroupRequest(role.getRoleName());

        mockMvc.perform(post("/api/v1/groups/{groupName}/roles", group.getGroupName())
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(success());

        assertThat(rolePermissionGroupMappingRepository.existsByRoleAndPermissionGroup(role, group)).isTrue();
    }

    @Test
    void assignRoleToSubGroup_withAdminToken_returns201() throws Exception {
        Role role = rolesRepository.save(RoleTestDataBuilder.aRole().build());
        PermissionGroup parent = permissionGroupsRepository.save(PermissionGroupTestDataBuilder.aPermissionGroup().build());
        SubPermissionGroup subGroup = persistSubGroup(parent);
        AssignRoleToSubGroupRequest request = new AssignRoleToSubGroupRequest(role.getRoleName());

        mockMvc.perform(post("/api/v1/groups/{parentGroupName}/subgroups/{subGroupName}/roles",
                        parent.getGroupName(), subGroup.getGroupName())
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(success());
    }

    @Test
    void addUsersToGroup_withAdminToken_returns201AndPropagatesTheGroupsRolesToTheUser() throws Exception {
        Role role = rolesRepository.save(RoleTestDataBuilder.aRole().build());
        PermissionGroup group = permissionGroupsRepository.save(PermissionGroupTestDataBuilder.aPermissionGroup().build());
        RolePermissionGroupMapping mapping = new RolePermissionGroupMapping();
        mapping.setRole(role);
        mapping.setPermissionGroup(group);
        mapping.setCreatedAt(LocalDateTime.now());
        rolePermissionGroupMappingRepository.save(mapping);
        User user = persistUser();
        AddUserToGroupRequest request = new AddUserToGroupRequest(user.getUsername());

        mockMvc.perform(post("/api/v1/groups/{groupName}/users", group.getGroupName())
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(success());

        assertThat(userPermissionGroupRepository.existsByUserUsernameAndPermissionGroupGroupName(
                user.getUsername(), group.getGroupName())).isTrue();
        assertThat(userRolesRepository.existsByUsernameAndRoleName(user.getUsername(), role.getRoleName())).isTrue();
    }

    @Test
    void addUsersToSubGroup_withAdminToken_returns201() throws Exception {
        PermissionGroup parent = permissionGroupsRepository.save(PermissionGroupTestDataBuilder.aPermissionGroup().build());
        SubPermissionGroup subGroup = persistSubGroup(parent);
        User user = persistUser();
        AddUserToSubGroupRequest request = new AddUserToSubGroupRequest(user.getUsername());

        mockMvc.perform(post("/api/v1/groups/{parentGroupName}/subgroups/{subGroupName}/users",
                        parent.getGroupName(), subGroup.getGroupName())
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(success());
    }

    @Test
    void addUsersToSubGroups_withAdminToken_returns201() throws Exception {
        PermissionGroup parent = permissionGroupsRepository.save(PermissionGroupTestDataBuilder.aPermissionGroup().build());
        SubPermissionGroup subGroupOne = persistSubGroup(parent);
        SubPermissionGroup subGroupTwo = persistSubGroup(parent);
        User user = persistUser();
        AddUserToSubGroupsRequest request =
                new AddUserToSubGroupsRequest(List.of(subGroupOne.getGroupName(), subGroupTwo.getGroupName()));

        mockMvc.perform(post("/api/v1/groups/{parentGroupName}/users/{username}/subgroups",
                        parent.getGroupName(), user.getUsername())
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(success());
    }

    @Test
    void unassignRole_withAdminToken_returns200AndRemovesTheMapping() throws Exception {
        Role role = rolesRepository.save(RoleTestDataBuilder.aRole().build());
        User user = persistUser();
        UserRole userRole = new UserRole();
        userRole.setUser(user);
        userRole.setRole(role);
        userRole.setCreatedAt(LocalDateTime.now());
        userRolesRepository.save(userRole);

        mockMvc.perform(delete("/api/v1/users/{username}/roles/{roleName}", user.getUsername(), role.getRoleName())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(success());

        assertThat(userRolesRepository.existsByUsernameAndRoleName(user.getUsername(), role.getRoleName())).isFalse();
    }

    @Test
    void removeUserFromGroup_withAdminToken_returns200AndRemovesTheMapping() throws Exception {
        PermissionGroup group = permissionGroupsRepository.save(PermissionGroupTestDataBuilder.aPermissionGroup().build());
        User user = persistUser();
        UserPermissionGroup userPermissionGroup = new UserPermissionGroup();
        userPermissionGroup.setUser(user);
        userPermissionGroup.setPermissionGroup(group);
        userPermissionGroup.setCreatedAt(LocalDateTime.now());
        userPermissionGroupRepository.save(userPermissionGroup);

        mockMvc.perform(delete("/api/v1/groups/{groupName}/users/{username}", group.getGroupName(), user.getUsername())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(success());

        assertThat(userPermissionGroupRepository.existsByUserUsernameAndPermissionGroupGroupName(
                user.getUsername(), group.getGroupName())).isFalse();
    }

    @Test
    void deleteParentGroup_withAdminToken_returns200AndDeletesTheGroup() throws Exception {
        PermissionGroup group = permissionGroupsRepository.save(PermissionGroupTestDataBuilder.aPermissionGroup().build());

        mockMvc.perform(delete("/api/v1/groups/{groupName}", group.getGroupName())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(success());

        assertThat(permissionGroupsRepository.existsByGroupName(group.getGroupName())).isFalse();
    }

    @Test
    void fetchPermissionGroupByName_withAdminToken_returns200() throws Exception {
        PermissionGroup group = permissionGroupsRepository.save(PermissionGroupTestDataBuilder.aPermissionGroup().build());

        mockMvc.perform(get("/api/v1/groups/{groupName}", group.getGroupName())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(success());
    }

    @Test
    void fetchSubPermissionGroupByName_withAdminToken_returns200() throws Exception {
        PermissionGroup parent = permissionGroupsRepository.save(PermissionGroupTestDataBuilder.aPermissionGroup().build());
        SubPermissionGroup subGroup = persistSubGroup(parent);

        mockMvc.perform(get("/api/v1/groups/{parentGroupName}/subgroups/{subGroupName}",
                        parent.getGroupName(), subGroup.getGroupName())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(success());
    }

    @Test
    void fetchSubPermissionGroupUsersByName_withAdminToken_returns200() throws Exception {
        PermissionGroup parent = permissionGroupsRepository.save(PermissionGroupTestDataBuilder.aPermissionGroup().build());
        SubPermissionGroup subGroup = persistSubGroup(parent);

        mockMvc.perform(get("/api/v1/groups/{parentGroupName}/subgroups/{subGroupName}/users",
                        parent.getGroupName(), subGroup.getGroupName())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(success());
    }

    @Test
    void fetchUserPermissionGroups_withAdminToken_returns200() throws Exception {
        User user = persistUser();

        mockMvc.perform(get("/api/v1/users/{username}/permission-groups", user.getUsername())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(success());
    }

    @Test
    void fetchUserRoles_withAdminToken_returns200() throws Exception {
        User user = persistUser();

        mockMvc.perform(get("/api/v1/users/{username}/roles", user.getUsername())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(success());
    }
}

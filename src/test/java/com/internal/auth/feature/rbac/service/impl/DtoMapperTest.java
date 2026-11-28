package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionErrorCode;
import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.rbac.model.PermissionGroup;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.model.RolePermissionGroupMapping;
import com.internal.auth.feature.rbac.model.SubPermissionGroup;
import com.internal.auth.feature.rbac.model.UserPermissionGroup;
import com.internal.auth.feature.rbac.model.UserRole;
import com.internal.auth.feature.rbac.repository.UserPermissionGroupRepository;
import com.internal.auth.feature.rbac.response.GroupCreationResponse;
import com.internal.auth.feature.rbac.response.GroupResponse;
import com.internal.auth.feature.rbac.response.PermissionGroupResponse;
import com.internal.auth.feature.rbac.response.RoleAndPermissionGroupMappingResponse;
import com.internal.auth.feature.rbac.response.RoleResponse;
import com.internal.auth.feature.rbac.response.SubGroupCreationResponse;
import com.internal.auth.feature.rbac.response.SubGroupResponse;
import com.internal.auth.feature.rbac.response.UserPermissionGroupResponse;
import com.internal.auth.feature.rbac.response.UserRoleResponse;
import com.internal.auth.feature.rbac.response.UserSubPermissionGroupResponse;
import com.internal.auth.testsupport.builder.PermissionGroupTestDataBuilder;
import com.internal.auth.testsupport.builder.RoleTestDataBuilder;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/** Unit tests for DtoMapper. */
class DtoMapperTest {

    private final UserPermissionGroupRepository userPermissionGroupRepository = mock(UserPermissionGroupRepository.class);
    private final DtoMapper mapper = new DtoMapper(userPermissionGroupRepository);

    @Test
    void createUserPermissionGroupResponseForSuperGroup_nullGroup_throws() {
        assertThatThrownBy(() -> mapper.createUserPermissionGroupResponseForSuperGroup(null, List.of()))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.PERMISSION_GROUP_NOT_FOUND));
    }

    @Test
    void createUserPermissionGroupResponseForSuperGroup_mapsFieldsRolesAndUsers() {
        PermissionGroup group = PermissionGroupTestDataBuilder.aPermissionGroup()
                .withGroupName("buyers")
                .withDescription("Buyer-facing endpoints")
                .build();
        group.setId(10L);

        Role role = RoleTestDataBuilder.aRole().withRoleName("buyer").withDescription("Buyer role").build();
        role.setId(20L);
        RolePermissionGroupMapping mapping = new RolePermissionGroupMapping();
        mapping.setRole(role);
        mapping.setPermissionGroup(group);
        group.setRolePermissionGroupMappings(List.of(mapping));

        User user = UserTestDataBuilder.aUser().build();
        user.setId(30L);
        UserPermissionGroup userGroup = new UserPermissionGroup();
        userGroup.setUser(user);
        userGroup.setPermissionGroup(group);

        GroupResponse response = mapper.createUserPermissionGroupResponseForSuperGroup(group, List.of(userGroup));

        assertThat(response.getGroupId()).isEqualTo(10L);
        assertThat(response.getGroupName()).isEqualTo("buyers");
        assertThat(response.getDescription()).isEqualTo("Buyer-facing endpoints");
        assertThat(response.getRoles()).hasSize(1);
        assertThat(response.getRoles().get(0).getId()).isEqualTo(20L);
        assertThat(response.getRoles().get(0).getRoleName()).isEqualTo("buyer");
        assertThat(response.getUserResponses()).hasSize(1);
        assertThat(response.getUserResponses().get(0).getUserId()).isEqualTo(30L);
        assertThat(response.getUserResponses().get(0).getUsername()).isEqualTo(user.getUsername());
        assertThat(response.getUserResponses().get(0).getEmail()).isEqualTo(user.getEmail());
        assertThat(response.getUserResponses().get(0).getMembership()).isEmpty();
    }

    @Test
    void createUserPermissionGroupResponseForSuperGroup_noUserGroups_emptyUserResponses() {
        PermissionGroup group = PermissionGroupTestDataBuilder.aPermissionGroup().build();
        group.setId(11L);
        group.setRolePermissionGroupMappings(List.of());

        GroupResponse response = mapper.createUserPermissionGroupResponseForSuperGroup(group, null);

        assertThat(response.getUserResponses()).isEmpty();
        assertThat(response.getRoles()).isEmpty();
    }

    @Test
    void createUserPermissionGroupResponseForSubGroup_emptyList_throws() {
        assertThatThrownBy(() -> mapper.createUserPermissionGroupResponseForSubGroup(List.of()))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_FIELD));
    }

    @Test
    void createUserPermissionGroupResponseForSubGroup_missingSubGroupOnFirstElement_throws() {
        UserPermissionGroup userGroup = new UserPermissionGroup();

        assertThatThrownBy(() -> mapper.createUserPermissionGroupResponseForSubGroup(List.of(userGroup)))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.SUB_GROUP_NOT_FOUND));
    }

    @Test
    void createUserPermissionGroupResponseForSubGroup_mapsFields() {
        SubPermissionGroup subGroup = new SubPermissionGroup();
        subGroup.setId(40L);
        subGroup.setGroupName("buyers-tier1");
        subGroup.setDescription("Tier 1 buyers");
        subGroup.setRolePermissionGroupMappings(List.of());

        UserPermissionGroup userGroup = new UserPermissionGroup();
        userGroup.setSubPermissionGroup(subGroup);
        User user = UserTestDataBuilder.aUser().build();
        user.setId(50L);
        userGroup.setUser(user);

        SubGroupResponse response = mapper.createUserPermissionGroupResponseForSubGroup(List.of(userGroup));

        assertThat(response.getSubGroupId()).isEqualTo(40L);
        assertThat(response.getSubgroupName()).isEqualTo("buyers-tier1");
        assertThat(response.getDescription()).isEqualTo("Tier 1 buyers");
        assertThat(response.getUserResponses()).hasSize(1);
        assertThat(response.getUserResponses().get(0).getUserId()).isEqualTo(50L);
    }

    @Test
    void buildPermissionGroupResponse_mapsFields() {
        PermissionGroup group = PermissionGroupTestDataBuilder.aPermissionGroup()
                .withGroupName("sellers")
                .withDescription("Seller-facing endpoints")
                .build();
        group.setId(60L);

        GroupCreationResponse response = mapper.buildPermissionGroupResponse(group);

        assertThat(response.getGroupId()).isEqualTo(60L);
        assertThat(response.getGroupName()).isEqualTo("sellers");
        assertThat(response.getDescription()).isEqualTo("Seller-facing endpoints");
    }

    @Test
    void buildSubPermissionGroupResponse_mapsFieldsIncludingParentGroupId() {
        PermissionGroup parent = PermissionGroupTestDataBuilder.aPermissionGroup().build();
        parent.setId(70L);

        SubPermissionGroup subGroup = new SubPermissionGroup();
        subGroup.setId(71L);
        subGroup.setGroupName("sellers-tier1");
        subGroup.setDescription("Tier 1 sellers");
        subGroup.setParentGroup(parent);

        SubGroupCreationResponse response = mapper.buildSubPermissionGroupResponse(subGroup);

        assertThat(response.getGroupId()).isEqualTo(71L);
        assertThat(response.getGroupName()).isEqualTo("sellers-tier1");
        assertThat(response.getDescription()).isEqualTo("Tier 1 sellers");
        assertThat(response.getSuperGroupId()).isEqualTo(70L);
    }

    @Test
    void buildRoleResponse_mapsFields() {
        Role role = RoleTestDataBuilder.aRole().withRoleName("admin").withDescription("Full access").build();
        role.setId(80L);

        RoleResponse response = mapper.buildRoleResponse(role);

        assertThat(response.getRoleId()).isEqualTo(80L);
        assertThat(response.getRoleName()).isEqualTo("admin");
        assertThat(response.getDescription()).isEqualTo("Full access");
        assertThat(response.getStatusCode()).isZero();
    }

    @Test
    void buildRoleAndPermissionGroupMappingResponse_mapsFields() {
        Role role = RoleTestDataBuilder.aRole().withRoleName("buyer").build();
        PermissionGroup group = PermissionGroupTestDataBuilder.aPermissionGroup().withGroupName("buyers").build();

        RolePermissionGroupMapping mapping = new RolePermissionGroupMapping();
        mapping.setId(90L);
        mapping.setRole(role);
        mapping.setPermissionGroup(group);

        RoleAndPermissionGroupMappingResponse response = mapper.buildRoleAndPermissionGroupMappingResponse(mapping);

        assertThat(response.getId()).isEqualTo(90L);
        assertThat(response.getRoleName()).isEqualTo("buyer");
        assertThat(response.getGroupName()).isEqualTo("buyers");
    }

    @Test
    void buildUserRole_mapsFields() {
        User user = UserTestDataBuilder.aUser().build();
        user.setId(100L);
        Role role = RoleTestDataBuilder.aRole().build();
        role.setId(101L);

        UserRole userRole = new UserRole();
        userRole.setId(102L);
        userRole.setUser(user);
        userRole.setRole(role);

        UserRoleResponse response = mapper.buildUserRole(userRole);

        assertThat(response.getId()).isEqualTo(102L);
        assertThat(response.getUserId()).isEqualTo(100L);
        assertThat(response.getRoleId()).isEqualTo(101L);
    }

    @Test
    void buildUserPermissionGroup_nullGroup_throws() {
        assertThatThrownBy(() -> mapper.buildUserPermissionGroup(null))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_REQUEST));
    }

    @Test
    void buildUserPermissionGroup_mapsAllPresentFields() {
        User user = UserTestDataBuilder.aUser().build();
        user.setId(110L);
        PermissionGroup group = PermissionGroupTestDataBuilder.aPermissionGroup().build();
        group.setId(111L);

        UserPermissionGroup userGroup = new UserPermissionGroup();
        userGroup.setId(112L);
        userGroup.setUser(user);
        userGroup.setPermissionGroup(group);

        UserPermissionGroupResponse response = mapper.buildUserPermissionGroup(userGroup);

        assertThat(response.getId()).isEqualTo(112L);
        assertThat(response.getUserId()).isEqualTo(110L);
        assertThat(response.getGroupId()).isEqualTo(111L);
    }

    @Test
    void buildUserPermissionGroup_missingUserAndGroup_leavesThoseFieldsNull() {
        UserPermissionGroup userGroup = new UserPermissionGroup();
        userGroup.setId(113L);

        UserPermissionGroupResponse response = mapper.buildUserPermissionGroup(userGroup);

        assertThat(response.getId()).isEqualTo(113L);
        assertThat(response.getUserId()).isNull();
        assertThat(response.getGroupId()).isNull();
    }

    @Test
    void buildUserPermissionGroups_emptyList_returnsEmptyList() {
        assertThat(mapper.buildUserPermissionGroups(List.of())).isEmpty();
    }

    @Test
    void buildUserPermissionGroups_mapsEachElement() {
        UserPermissionGroup first = new UserPermissionGroup();
        first.setId(120L);
        UserPermissionGroup second = new UserPermissionGroup();
        second.setId(121L);

        List<UserPermissionGroupResponse> responses = mapper.buildUserPermissionGroups(List.of(first, second));

        assertThat(responses).hasSize(2);
        assertThat(responses.get(0).getId()).isEqualTo(120L);
        assertThat(responses.get(1).getId()).isEqualTo(121L);
    }

    @Test
    void buildUserSubPermissionGroup_nullGroup_throws() {
        assertThatThrownBy(() -> mapper.buildUserSubPermissionGroup(null))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.EMPTY_REQUEST));
    }

    @Test
    void buildUserSubPermissionGroup_mapsAllPresentFieldsIncludingSubGroupId() {
        User user = UserTestDataBuilder.aUser().build();
        user.setId(130L);
        PermissionGroup group = PermissionGroupTestDataBuilder.aPermissionGroup().build();
        group.setId(131L);
        SubPermissionGroup subGroup = new SubPermissionGroup();
        subGroup.setId(132L);

        UserPermissionGroup userGroup = new UserPermissionGroup();
        userGroup.setId(133L);
        userGroup.setUser(user);
        userGroup.setPermissionGroup(group);
        userGroup.setSubPermissionGroup(subGroup);

        UserSubPermissionGroupResponse response = mapper.buildUserSubPermissionGroup(userGroup);

        assertThat(response.getId()).isEqualTo(133L);
        assertThat(response.getUserId()).isEqualTo(130L);
        assertThat(response.getGroupId()).isEqualTo(131L);
        assertThat(response.getSubGroupId()).isEqualTo(132L);
    }

    @Test
    void buildUserGroupsResponse_emptyList_returnsEmptyList() {
        assertThat(mapper.buildUserGroupsResponse(List.of())).isEmpty();
    }

    @Test
    void buildUserGroupsResponse_mapsEachGroup() {
        PermissionGroup group = PermissionGroupTestDataBuilder.aPermissionGroup()
                .withGroupName("buyers")
                .withDescription("desc")
                .build();
        group.setId(140L);

        List<PermissionGroupResponse> responses = mapper.buildUserGroupsResponse(List.of(group));

        assertThat(responses).hasSize(1);
        assertThat(responses.get(0).getGroupId()).isEqualTo(140L);
        assertThat(responses.get(0).getGroupName()).isEqualTo("buyers");
        assertThat(responses.get(0).getDescription()).isEqualTo("desc");
    }

    @Test
    void buildUserRoleResponse_emptyList_returnsEmptyList() {
        assertThat(mapper.buildUserRoleResponse(List.of())).isEmpty();
    }

    @Test
    void buildUserRoleResponse_mapsEachRole() {
        Role role = RoleTestDataBuilder.aRole().withRoleName("buyer").withDescription("desc").build();
        role.setId(150L);

        List<RoleResponse> responses = mapper.buildUserRoleResponse(List.of(role));

        assertThat(responses).hasSize(1);
        assertThat(responses.get(0).getRoleId()).isEqualTo(150L);
        assertThat(responses.get(0).getRoleName()).isEqualTo("buyer");
        assertThat(responses.get(0).getDescription()).isEqualTo("desc");
    }
}

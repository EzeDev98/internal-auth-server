package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionErrorCode;
import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.rbac.repository.*;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Unit tests for EntityUtilityService user lookup. */
class EntityUtilityServiceGetUserTest {

    private final UserRepository userRepository = mock(UserRepository.class);

    private final EntityUtilityService service = new EntityUtilityService(
            mock(SubPermissionGroupRepository.class),
            mock(PermissionGroupsRepository.class),
            mock(UserPermissionGroupRepository.class),
            mock(RolesRepository.class),
            mock(RolePermissionGroupMappingRepository.class),
            mock(UserRolesRepository.class),
            userRepository);

    @Test
    void getUser_noMatches_throwsUserNotFound() {
        when(userRepository.findAllByUsername("ghost")).thenReturn(List.of());

        assertThatThrownBy(() -> service.getUser("ghost"))
                .isInstanceOfSatisfying(PermissionException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.USER_NOT_FOUND));
    }

    @Test
    void getUser_exactlyOneMatch_returnsIt() {
        User user = UserTestDataBuilder.aUser().withUsername("buyer1").withClientApplicationId(1L).build();
        when(userRepository.findAllByUsername("buyer1")).thenReturn(List.of(user));

        User result = service.getUser("buyer1");

        assertThat(result).isSameAs(user);
    }

    @Test
    void getUser_sameUsernameInTwoTenants_throwsAmbiguousUsernameConflict() {
        User tenantOneUser = UserTestDataBuilder.aUser().withUsername("shared_username").withClientApplicationId(1L).build();
        User tenantTwoUser = UserTestDataBuilder.aUser().withUsername("shared_username").withClientApplicationId(2L).build();
        when(userRepository.findAllByUsername("shared_username"))
                .thenReturn(List.of(tenantOneUser, tenantTwoUser));

        assertThatThrownBy(() -> service.getUser("shared_username"))
                .isInstanceOfSatisfying(PermissionException.class, ex -> {
                    assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.AMBIGUOUS_USERNAME);
                    assertThat(ex.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                });
    }
}

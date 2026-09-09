package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.common.exception.PermissionErrorCode;
import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.common.exception.UserAlreadyExistsException;
import com.internal.auth.common.reset.ResetValidator;
import com.internal.auth.common.response.BaseResponse;
import com.internal.auth.common.security.AuthenticationHelper;
import com.internal.auth.feature.identity.dto.request.AdminRegisterRequest;
import com.internal.auth.feature.identity.dto.response.AdminRegisterResponse;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.identity.validation.RegistrationValidator;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.repository.RolesRepository;
import com.internal.auth.feature.rbac.repository.UserRolesRepository;
import com.internal.auth.feature.rbac.service.UserService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AdminRegistrationServiceImplTest {

    private static final Long CLIENT_APP_ID = 1L;
    private static final String ADMIN_ROLE = "create-admin";

    private final UserRepository userRepository = mock(UserRepository.class);
    private final RegistrationValidator registrationValidator = mock(RegistrationValidator.class);
    private final ResetValidator resetValidator = mock(ResetValidator.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final UserService userService = mock(UserService.class);
    private final UserRolesRepository userRolesRepository = mock(UserRolesRepository.class);
    private final AuthenticationHelper authenticationHelper = mock(AuthenticationHelper.class);
    private final RolesRepository rolesRepository = mock(RolesRepository.class);

    private final AdminRegistrationServiceImpl service = new AdminRegistrationServiceImpl(
            userRepository, registrationValidator, resetValidator, passwordEncoder,
            userService, userRolesRepository, authenticationHelper, rolesRepository);

    private static AdminRegisterRequest validRequest() {
        return new AdminRegisterRequest("newadmin", "+23480000000", "admin@wm.com", "Passw0rd!", "Passw0rd!");
    }

    private static User savedUserWithId(long id) {
        User saved = new User();
        saved.setId(id);
        saved.setUsername("newadmin");
        return saved;
    }

    private static Role role(String name) {
        Role role = new Role();
        role.setRoleName(name);
        return role;
    }

    /** Bypasses the bootstrap gate entirely (caller already an admin) so a test can focus on what comes after it. */
    private void asAuthenticatedAdmin() {
        when(authenticationHelper.isAdmin()).thenReturn(true);
    }

    /** Puts the gate on its "no admin exists yet, proceed" path with the role row already present. */
    private void asFirstAdminBootstrap() {
        when(authenticationHelper.isAdmin()).thenReturn(false);
        when(rolesRepository.existsByRoleName(ADMIN_ROLE)).thenReturn(true);
        when(rolesRepository.findByRoleNameForUpdate(ADMIN_ROLE)).thenReturn(Optional.of(role(ADMIN_ROLE)));
        when(userRolesRepository.existsByRoleRoleName(ADMIN_ROLE)).thenReturn(false);
    }

    private void stubUniquenessChecksPass() {
        when(userRepository.findByUsernameAndClientApplicationId("newadmin", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(userRepository.findByPhoneNumberAndClientApplicationId("+23480000000", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(userRepository.findByEmailAndClientApplicationId("admin@wm.com", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(passwordEncoder.encode("Passw0rd!")).thenReturn("hashed");
    }

    // ===================== self-limiting bootstrap gate ====================

    @Test
    void register_callerIsAlreadyAdmin_skipsBootstrapGateEntirely() {
        asAuthenticatedAdmin();
        stubUniquenessChecksPass();
        when(userRepository.save(any(User.class))).thenReturn(savedUserWithId(1L));
        when(userService.addUserToAdminPermissionGroup("newadmin")).thenReturn(new BaseResponse(201));

        service.register(validRequest(), CLIENT_APP_ID);

        verifyNoInteractions(rolesRepository);
        verify(userRolesRepository, never()).existsByRoleRoleName(anyString());
    }

    @Test
    void register_currentBehavior_notAdmin_locksRoleRowForUpdateBeforeCheckingExistingAdmin() {
        // The Step 5 TOCTOU fix only works in this order: acquire the lock,
        // THEN check whether an admin already exists. Reversing the order
        // would let two concurrent callers both observe "no admin yet"
        // before either one's lock (and insert) is visible to the other.
        asFirstAdminBootstrap();
        stubUniquenessChecksPass();
        when(userRepository.save(any(User.class))).thenReturn(savedUserWithId(1L));
        when(userService.addUserToAdminPermissionGroup("newadmin")).thenReturn(new BaseResponse(201));

        service.register(validRequest(), CLIENT_APP_ID);

        InOrder inOrder = inOrder(rolesRepository, userRolesRepository);
        inOrder.verify(rolesRepository).findByRoleNameForUpdate(ADMIN_ROLE);
        inOrder.verify(userRolesRepository).existsByRoleRoleName(ADMIN_ROLE);
    }

    @Test
    void register_notAdminAndAdminAlreadyExists_throwsAccessDeniedAndNeverValidatesOrRegisters() {
        when(authenticationHelper.isAdmin()).thenReturn(false);
        when(rolesRepository.existsByRoleName(ADMIN_ROLE)).thenReturn(true);
        when(rolesRepository.findByRoleNameForUpdate(ADMIN_ROLE)).thenReturn(Optional.of(role(ADMIN_ROLE)));
        when(userRolesRepository.existsByRoleRoleName(ADMIN_ROLE)).thenReturn(true);

        assertThatThrownBy(() -> service.register(validRequest(), CLIENT_APP_ID))
                .isInstanceOfSatisfying(AccessDeniedException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo(
                                "An admin already exists - further admin accounts must be created by an existing admin."));

        verifyNoInteractions(registrationValidator, resetValidator, passwordEncoder, userService);
        verify(userRepository, never()).save(any());
    }

    @Test
    void register_bootstrap_roleRowMissing_createsItBeforeAttemptingTheLock() {
        when(authenticationHelper.isAdmin()).thenReturn(false);
        when(rolesRepository.existsByRoleName(ADMIN_ROLE)).thenReturn(false);
        when(rolesRepository.findByRoleNameForUpdate(ADMIN_ROLE)).thenReturn(Optional.of(role(ADMIN_ROLE)));
        when(userRolesRepository.existsByRoleRoleName(ADMIN_ROLE)).thenReturn(false);
        stubUniquenessChecksPass();
        when(userRepository.save(any(User.class))).thenReturn(savedUserWithId(1L));
        when(userService.addUserToAdminPermissionGroup("newadmin")).thenReturn(new BaseResponse(201));

        service.register(validRequest(), CLIENT_APP_ID);

        ArgumentCaptor<Role> roleCaptor = ArgumentCaptor.forClass(Role.class);
        InOrder inOrder = inOrder(rolesRepository);
        inOrder.verify(rolesRepository).save(roleCaptor.capture());
        inOrder.verify(rolesRepository).findByRoleNameForUpdate(ADMIN_ROLE);
        assertThat(roleCaptor.getValue().getRoleName()).isEqualTo(ADMIN_ROLE);
        assertThat(roleCaptor.getValue().getDescription()).isEqualTo(
                "Full administrative access - equivalent to Keycloak's realm-admin role. Can manage users, roles, permission groups, client applications, sessions, and signing keys.");
    }

    @Test
    void register_bootstrap_roleRowAlreadyExists_neverCreatesItAgain() {
        asFirstAdminBootstrap();
        stubUniquenessChecksPass();
        when(userRepository.save(any(User.class))).thenReturn(savedUserWithId(1L));
        when(userService.addUserToAdminPermissionGroup("newadmin")).thenReturn(new BaseResponse(201));

        service.register(validRequest(), CLIENT_APP_ID);

        verify(rolesRepository, never()).save(any());
    }

    @Test
    void register_currentBehavior_roleRowCreationRace_swallowsDataIntegrityAndProceedsToLock() {
        when(authenticationHelper.isAdmin()).thenReturn(false);
        when(rolesRepository.existsByRoleName(ADMIN_ROLE)).thenReturn(false);
        when(rolesRepository.save(any(Role.class))).thenThrow(new DataIntegrityViolationException("duplicate role_name"));
        when(rolesRepository.findByRoleNameForUpdate(ADMIN_ROLE)).thenReturn(Optional.of(role(ADMIN_ROLE)));
        when(userRolesRepository.existsByRoleRoleName(ADMIN_ROLE)).thenReturn(false);
        stubUniquenessChecksPass();
        when(userRepository.save(any(User.class))).thenReturn(savedUserWithId(1L));
        when(userService.addUserToAdminPermissionGroup("newadmin")).thenReturn(new BaseResponse(201));

        assertThatCode(() -> service.register(validRequest(), CLIENT_APP_ID)).doesNotThrowAnyException();

        verify(rolesRepository).findByRoleNameForUpdate(ADMIN_ROLE);
    }

    // ===================== validation delegation (gate bypassed via admin caller) ====================

    @Test
    void register_usernameValidationFails_propagatesAndNeverTouchesRepository() {
        asAuthenticatedAdmin();
        AdminRegisterRequest request = validRequest();
        doThrow(new BadRequestException("Username is required"))
                .when(registrationValidator).validateUsername(request.getUsername());

        assertThatThrownBy(() -> service.register(request, CLIENT_APP_ID))
                .isInstanceOf(BadRequestException.class);

        verifyNoInteractions(userRepository, passwordEncoder, userService);
    }

    @Test
    void register_contactInfoMissing_propagatesAndNeverTouchesRepository() {
        asAuthenticatedAdmin();
        AdminRegisterRequest request = validRequest();
        doThrow(new BadRequestException("At least one of phone number or email is required"))
                .when(registrationValidator).validateContactInfoPresent(request.getPhoneNumber(), request.getEmail());

        assertThatThrownBy(() -> service.register(request, CLIENT_APP_ID))
                .isInstanceOf(BadRequestException.class);
        verifyNoInteractions(userRepository);
    }

    @Test
    void register_phoneFormatInvalid_propagatesAndNeverTouchesRepository() {
        asAuthenticatedAdmin();
        AdminRegisterRequest request = validRequest();
        doThrow(new BadRequestException("Please enter a valid phone number"))
                .when(registrationValidator).validatePhoneNumberIfPresent(request.getPhoneNumber());

        assertThatThrownBy(() -> service.register(request, CLIENT_APP_ID))
                .isInstanceOf(BadRequestException.class);
        verifyNoInteractions(userRepository);
    }

    @Test
    void register_emailFormatInvalid_propagatesAndNeverTouchesRepository() {
        asAuthenticatedAdmin();
        AdminRegisterRequest request = validRequest();
        doThrow(new BadRequestException("Please enter a valid email address"))
                .when(registrationValidator).validateEmailIfPresent(request.getEmail());

        assertThatThrownBy(() -> service.register(request, CLIENT_APP_ID))
                .isInstanceOf(BadRequestException.class);
        verifyNoInteractions(userRepository);
    }

    @Test
    void register_passwordInvalid_propagatesAndNeverTouchesRepository() {
        asAuthenticatedAdmin();
        AdminRegisterRequest request = validRequest();
        doThrow(new BadRequestException("Password must be at least 8 characters"))
                .when(resetValidator).validateNewPassword(request.getPassword(), request.getConfirmPassword());

        assertThatThrownBy(() -> service.register(request, CLIENT_APP_ID))
                .isInstanceOf(BadRequestException.class);
        verifyNoInteractions(userRepository);
    }

    // ===================== per-tenant uniqueness checks ====================

    @Test
    void register_usernameAlreadyTakenForTenant_throwsGenericConflictAndStopsBeforePhoneOrEmailChecks() {
        asAuthenticatedAdmin();
        when(userRepository.findByUsernameAndClientApplicationId("newadmin", CLIENT_APP_ID))
                .thenReturn(Optional.of(new User()));

        assertThatThrownBy(() -> service.register(validRequest(), CLIENT_APP_ID))
                .isInstanceOfSatisfying(UserAlreadyExistsException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("Username or password is incorrect"));

        verify(userRepository, never()).findByPhoneNumberAndClientApplicationId(anyString(), any());
        verify(userRepository, never()).findByEmailAndClientApplicationId(anyString(), any());
        verify(userRepository, never()).save(any());
    }

    @Test
    void register_phoneAlreadyTakenForTenant_throwsGenericConflictAndStopsBeforeEmailCheck() {
        asAuthenticatedAdmin();
        when(userRepository.findByUsernameAndClientApplicationId("newadmin", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(userRepository.findByPhoneNumberAndClientApplicationId("+23480000000", CLIENT_APP_ID))
                .thenReturn(Optional.of(new User()));

        assertThatThrownBy(() -> service.register(validRequest(), CLIENT_APP_ID))
                .isInstanceOfSatisfying(UserAlreadyExistsException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("Phone number or password is incorrect"));

        verify(userRepository, never()).findByEmailAndClientApplicationId(anyString(), any());
        verify(userRepository, never()).save(any());
    }

    @Test
    void register_emailAlreadyTakenForTenant_throwsGenericConflict() {
        asAuthenticatedAdmin();
        when(userRepository.findByUsernameAndClientApplicationId("newadmin", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(userRepository.findByPhoneNumberAndClientApplicationId("+23480000000", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(userRepository.findByEmailAndClientApplicationId("admin@wm.com", CLIENT_APP_ID))
                .thenReturn(Optional.of(new User()));

        assertThatThrownBy(() -> service.register(validRequest(), CLIENT_APP_ID))
                .isInstanceOfSatisfying(UserAlreadyExistsException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("Email or password is incorrect"));

        verify(userRepository, never()).save(any());
    }

    @Test
    void register_blankOrWhitespacePhoneAndEmail_normalizedToNullAndSkipTheirUniquenessChecks() {
        asAuthenticatedAdmin();
        AdminRegisterRequest request = new AdminRegisterRequest("newadmin", "   ", "", "Passw0rd!", "Passw0rd!");
        when(userRepository.findByUsernameAndClientApplicationId("newadmin", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(passwordEncoder.encode("Passw0rd!")).thenReturn("hashed");
        User saved = savedUserWithId(3L);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User toSave = invocation.getArgument(0);
            assertThat(toSave.getPhoneNumber()).isNull();
            assertThat(toSave.getEmail()).isNull();
            assertThat(toSave.isEmailVerified()).isFalse();
            assertThat(toSave.isPhoneVerified()).isFalse();
            return saved;
        });
        when(userService.addUserToAdminPermissionGroup("newadmin")).thenReturn(new BaseResponse(201));

        service.register(request, CLIENT_APP_ID);

        verify(userRepository, never()).findByPhoneNumberAndClientApplicationId(anyString(), any());
        verify(userRepository, never()).findByEmailAndClientApplicationId(anyString(), any());
    }

    // ===================== success path / admin-specific differences ====================

    @Test
    void register_success_preVerifiesBothSuppliedContactMethodsImmediately() {
        asAuthenticatedAdmin();
        stubUniquenessChecksPass();
        User saved = savedUserWithId(42L);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User toSave = invocation.getArgument(0);
            assertThat(toSave.getClientApplicationId()).isEqualTo(CLIENT_APP_ID);
            assertThat(toSave.getUsername()).isEqualTo("newadmin");
            assertThat(toSave.getPassword()).isEqualTo("hashed");
            assertThat(toSave.isEnabled()).isTrue();
            assertThat(toSave.isEmailVerified()).isTrue();
            assertThat(toSave.isPhoneVerified()).isTrue();
            return saved;
        });
        when(userService.addUserToAdminPermissionGroup("newadmin")).thenReturn(new BaseResponse(201));

        service.register(validRequest(), CLIENT_APP_ID);
    }

    @Test
    void register_success_currentBehavior_onlySuppliedContactMethodIsMarkedVerified() {
        asAuthenticatedAdmin();
        AdminRegisterRequest request = new AdminRegisterRequest("newadmin", "+23480000000", null, "Passw0rd!", "Passw0rd!");
        when(userRepository.findByUsernameAndClientApplicationId("newadmin", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(userRepository.findByPhoneNumberAndClientApplicationId("+23480000000", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(passwordEncoder.encode("Passw0rd!")).thenReturn("hashed");
        User saved = savedUserWithId(43L);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User toSave = invocation.getArgument(0);
            assertThat(toSave.isPhoneVerified()).isTrue();
            assertThat(toSave.isEmailVerified()).isFalse();
            return saved;
        });
        when(userService.addUserToAdminPermissionGroup("newadmin")).thenReturn(new BaseResponse(201));

        service.register(request, CLIENT_APP_ID);
    }

    @Test
    void register_success_grantsAdminPermissionGroupNeverTheDefaultOne() {
        asAuthenticatedAdmin();
        stubUniquenessChecksPass();
        when(userRepository.save(any(User.class))).thenReturn(savedUserWithId(44L));
        when(userService.addUserToAdminPermissionGroup("newadmin")).thenReturn(new BaseResponse(201));

        service.register(validRequest(), CLIENT_APP_ID);

        verify(userService).addUserToAdminPermissionGroup("newadmin");
        verify(userService, never()).addUserToDefaultPermissionGroup(anyString());
    }

    @Test
    void register_success_returnsResponseWithSavedIdUsernameAndConfirmationMessage() {
        asAuthenticatedAdmin();
        stubUniquenessChecksPass();
        when(userRepository.save(any(User.class))).thenReturn(savedUserWithId(45L));
        when(userService.addUserToAdminPermissionGroup("newadmin")).thenReturn(new BaseResponse(201));

        AdminRegisterResponse response = service.register(validRequest(), CLIENT_APP_ID);

        assertThat(response.getUserId()).isEqualTo(45L);
        assertThat(response.getUsername()).isEqualTo("newadmin");
        assertThat(response.getMessage()).isEqualTo("Admin account created successfully.");
    }

    @Test
    void register_currentBehavior_adminRoleAssignmentFailureThrowsAndRollsBackUnlikeRegularRegistration() {
        // Contrast with RegistrationServiceImpl: a non-201 default-role
        // assignment there is soft-fail (logged, ignored). Here it throws,
        // because an admin account silently missing its admin role would be
        // an unrecoverable broken account (no admin yet exists to fix it).
        asAuthenticatedAdmin();
        stubUniquenessChecksPass();
        when(userRepository.save(any(User.class))).thenReturn(savedUserWithId(46L));
        when(userService.addUserToAdminPermissionGroup("newadmin")).thenReturn(new BaseResponse(500, "permission group unavailable"));

        assertThatThrownBy(() -> service.register(validRequest(), CLIENT_APP_ID))
                .isInstanceOfSatisfying(PermissionException.class, ex -> {
                    assertThat(ex.getErrorCode()).isEqualTo(PermissionErrorCode.INTERNAL_ERROR);
                    assertThat(ex.getMessage()).contains("Failed to grant admin role during admin registration")
                            .contains("permission group unavailable");
                });
    }

    @Test
    void register_currentBehavior_saveRaceLossIsWrappedAsUserAlreadyExistsAndSkipsRoleAssignment() {
        asAuthenticatedAdmin();
        stubUniquenessChecksPass();
        when(userRepository.save(any(User.class))).thenThrow(new DataIntegrityViolationException("duplicate key"));

        assertThatThrownBy(() -> service.register(validRequest(), CLIENT_APP_ID))
                .isInstanceOfSatisfying(UserAlreadyExistsException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("Unable to create account with the provided details"));

        verifyNoInteractions(userService);
    }
}

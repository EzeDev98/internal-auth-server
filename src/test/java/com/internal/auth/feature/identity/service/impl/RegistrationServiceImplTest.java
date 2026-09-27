package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.common.exception.UserAlreadyExistsException;
import com.internal.auth.common.reset.ResetValidator;
import com.internal.auth.common.response.BaseResponse;
import com.internal.auth.feature.identity.dto.request.RegisterRequest;
import com.internal.auth.feature.identity.dto.response.RegisterResponse;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.identity.service.EmailVerificationService;
import com.internal.auth.feature.identity.service.PhoneVerificationService;
import com.internal.auth.feature.identity.validation.RegistrationValidator;
import com.internal.auth.feature.rbac.service.UserService;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.InOrder;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class RegistrationServiceImplTest {

    private static final Long CLIENT_APP_ID = 7L;

    private final UserRepository userRepository = mock(UserRepository.class);
    private final RegistrationValidator registrationValidator = mock(RegistrationValidator.class);
    private final ResetValidator resetValidator = mock(ResetValidator.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final EmailVerificationService emailVerificationService = mock(EmailVerificationService.class);
    private final PhoneVerificationService phoneVerificationService = mock(PhoneVerificationService.class);
    private final UserService userService = mock(UserService.class);

    private final UserRegistrationServiceImpl service = new UserRegistrationServiceImpl(
            userRepository, registrationValidator, resetValidator, passwordEncoder,
            emailVerificationService, phoneVerificationService, userService);

    private static RegisterRequest validRequest() {
        return new RegisterRequest("newuser", "+23480000000", "new@user.com", "Passw0rd!", "Passw0rd!");
    }

    private static User savedUserWithId(String id) {
        User saved = new User();
        saved.setInternalAuthUserId(id);
        saved.setUsername("newuser");
        return saved;
    }

    private void stubUniquenessChecksPass() {
        when(userRepository.findByUsernameAndClientApplicationId("newuser", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(userRepository.findByPhoneNumberAndClientApplicationId("+23480000000", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(userRepository.findByEmailAndClientApplicationId("new@user.com", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(passwordEncoder.encode("Passw0rd!")).thenReturn("hashed");
    }

    // -- validation delegation ------------------------------------------------

    @Test
    void register_usernameValidationFails_propagatesAndNeverTouchesRepository() {
        RegisterRequest request = validRequest();
        doThrow(new BadRequestException("Username is required"))
                .when(registrationValidator).validateUsername(request.getUsername());

        assertThatThrownBy(() -> service.register(request, CLIENT_APP_ID)).isInstanceOf(BadRequestException.class);

        verifyNoInteractions(userRepository, passwordEncoder, emailVerificationService, phoneVerificationService, userService);
    }

    @Test
    void register_contactInfoMissing_propagatesAndNeverTouchesRepository() {
        RegisterRequest request = validRequest();
        doThrow(new BadRequestException("At least one of phone number or email is required"))
                .when(registrationValidator).validateContactInfoPresent(request.getPhoneNumber(), request.getEmail());

        assertThatThrownBy(() -> service.register(request, CLIENT_APP_ID)).isInstanceOf(BadRequestException.class);
        verifyNoInteractions(userRepository);
    }

    @Test
    void register_phoneFormatInvalid_propagatesAndNeverTouchesRepository() {
        RegisterRequest request = validRequest();
        doThrow(new BadRequestException("Please enter a valid phone number"))
                .when(registrationValidator).validatePhoneNumberIfPresent(request.getPhoneNumber());

        assertThatThrownBy(() -> service.register(request, CLIENT_APP_ID)).isInstanceOf(BadRequestException.class);
        verifyNoInteractions(userRepository);
    }

    @Test
    void register_emailFormatInvalid_propagatesAndNeverTouchesRepository() {
        RegisterRequest request = validRequest();
        doThrow(new BadRequestException("Please enter a valid email address"))
                .when(registrationValidator).validateEmailIfPresent(request.getEmail());

        assertThatThrownBy(() -> service.register(request, CLIENT_APP_ID)).isInstanceOf(BadRequestException.class);
        verifyNoInteractions(userRepository);
    }

    @Test
    void register_passwordInvalid_propagatesAndNeverTouchesRepository() {
        RegisterRequest request = validRequest();
        doThrow(new BadRequestException("Password must be at least 8 characters"))
                .when(resetValidator).validateNewPassword(request.getPassword(), request.getConfirmPassword());

        assertThatThrownBy(() -> service.register(request, CLIENT_APP_ID)).isInstanceOf(BadRequestException.class);
        verifyNoInteractions(userRepository);
    }

    @Test
    void register_callsAllFiveValidationStepsInOrderBeforeAnyUniquenessCheck() {
        RegisterRequest request = validRequest();
        stubUniquenessChecksPass();
        when(userRepository.save(any(User.class))).thenReturn(savedUserWithId("String123@"));
        when(userService.addUserToDefaultPermissionGroup("newuser")).thenReturn(new BaseResponse(201));

        service.register(request, CLIENT_APP_ID);

        InOrder inOrder = inOrder(registrationValidator, resetValidator, userRepository);
        inOrder.verify(registrationValidator).validateUsername(request.getUsername());
        inOrder.verify(registrationValidator).validateContactInfoPresent(request.getPhoneNumber(), request.getEmail());
        inOrder.verify(registrationValidator).validatePhoneNumberIfPresent(request.getPhoneNumber());
        inOrder.verify(registrationValidator).validateEmailIfPresent(request.getEmail());
        inOrder.verify(resetValidator).validateNewPassword(request.getPassword(), request.getConfirmPassword());
        inOrder.verify(userRepository).findByUsernameAndClientApplicationId("newuser", CLIENT_APP_ID);
    }

    @Test
    void register_currentBehavior_usernameValidatorReceivesRawValueNotTrimmed() {
        RegisterRequest request = new RegisterRequest("  newuser  ", "+23480000000", "new@user.com", "Passw0rd!", "Passw0rd!");
        when(userRepository.findByUsernameAndClientApplicationId("newuser", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(userRepository.findByPhoneNumberAndClientApplicationId("+23480000000", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(userRepository.findByEmailAndClientApplicationId("new@user.com", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(passwordEncoder.encode("Passw0rd!")).thenReturn("hashed");
        when(userRepository.save(any(User.class))).thenReturn(savedUserWithId("String123@"));
        when(userService.addUserToDefaultPermissionGroup(anyString())).thenReturn(new BaseResponse(201));

        service.register(request, CLIENT_APP_ID);

        // Validator sees the raw, untrimmed value - only the copy used for
        // the uniqueness check and the saved entity gets trimmed.
        verify(registrationValidator).validateUsername("  newuser  ");
        verify(userRepository).findByUsernameAndClientApplicationId("newuser", CLIENT_APP_ID);
    }

    // -- per-tenant uniqueness checks -----------------------------------------

    @Test
    void register_usernameAlreadyTakenForTenant_throwsGenericConflictAndStopsBeforePhoneOrEmailChecks() {
        RegisterRequest request = validRequest();
        when(userRepository.findByUsernameAndClientApplicationId("newuser", CLIENT_APP_ID))
                .thenReturn(Optional.of(new User()));

        assertThatThrownBy(() -> service.register(request, CLIENT_APP_ID))
                .isInstanceOfSatisfying(UserAlreadyExistsException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("Username or password is incorrect"));

        verify(userRepository, never()).findByPhoneNumberAndClientApplicationId(anyString(), any());
        verify(userRepository, never()).findByEmailAndClientApplicationId(anyString(), any());
        verify(userRepository, never()).save(any());
    }

    @Test
    void register_phoneAlreadyTakenForTenant_throwsGenericConflictAndStopsBeforeEmailCheck() {
        RegisterRequest request = validRequest();
        when(userRepository.findByUsernameAndClientApplicationId("newuser", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(userRepository.findByPhoneNumberAndClientApplicationId("+23480000000", CLIENT_APP_ID))
                .thenReturn(Optional.of(new User()));

        assertThatThrownBy(() -> service.register(request, CLIENT_APP_ID))
                .isInstanceOfSatisfying(UserAlreadyExistsException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("Phone number or password is incorrect"));

        verify(userRepository, never()).findByEmailAndClientApplicationId(anyString(), any());
        verify(userRepository, never()).save(any());
    }

    @Test
    void register_emailAlreadyTakenForTenant_throwsGenericConflict() {
        RegisterRequest request = validRequest();
        when(userRepository.findByUsernameAndClientApplicationId("newuser", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(userRepository.findByPhoneNumberAndClientApplicationId("+23480000000", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(userRepository.findByEmailAndClientApplicationId("new@user.com", CLIENT_APP_ID))
                .thenReturn(Optional.of(new User()));

        assertThatThrownBy(() -> service.register(request, CLIENT_APP_ID))
                .isInstanceOfSatisfying(UserAlreadyExistsException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("Email or password is incorrect"));

        verify(userRepository, never()).save(any());
    }

    @Test
    void register_currentBehavior_uniquenessChecksAreScopedToGivenClientApplicationIdOnly() {
        // Same username taken under a different tenant must never block
        // this registration - and the check must never fall back to the
        // unscoped findByUsername/findByPhoneNumber/findByEmail.
        RegisterRequest request = validRequest();
        Long otherTenant = 99L;
        when(userRepository.findByUsernameAndClientApplicationId("newuser", otherTenant)).thenReturn(Optional.empty());
        when(userRepository.findByPhoneNumberAndClientApplicationId("+23480000000", otherTenant)).thenReturn(Optional.empty());
        when(userRepository.findByEmailAndClientApplicationId("new@user.com", otherTenant)).thenReturn(Optional.empty());
        when(passwordEncoder.encode("Passw0rd!")).thenReturn("hashed");
        when(userRepository.save(any(User.class))).thenReturn(savedUserWithId("String123@"));
        when(userService.addUserToDefaultPermissionGroup("newuser")).thenReturn(new BaseResponse(201));

        assertThatCode(() -> service.register(request, otherTenant)).doesNotThrowAnyException();

        verify(userRepository, never()).findByUsername(anyString());
        verify(userRepository, never()).findByPhoneNumber(anyString());
        verify(userRepository, never()).findByEmail(anyString());
    }

    @Test
    void register_blankOrWhitespacePhoneAndEmail_normalizedToNullAndSkipTheirUniquenessChecks() {
        RegisterRequest request = new RegisterRequest("newuser", "   ", "", "Passw0rd!", "Passw0rd!");
        when(userRepository.findByUsernameAndClientApplicationId("newuser", CLIENT_APP_ID)).thenReturn(Optional.empty());
        when(passwordEncoder.encode("Passw0rd!")).thenReturn("hashed");
        User saved = savedUserWithId("String123@");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User toSave = invocation.getArgument(0);
            assertThat(toSave.getPhoneNumber()).isNull();
            assertThat(toSave.getEmail()).isNull();
            return saved;
        });
        when(userService.addUserToDefaultPermissionGroup("newuser")).thenReturn(new BaseResponse(201));

        service.register(request, CLIENT_APP_ID);

        verify(userRepository, never()).findByPhoneNumberAndClientApplicationId(anyString(), any());
        verify(userRepository, never()).findByEmailAndClientApplicationId(anyString(), any());
    }

    // -- successful save, dual verification triggers, default role -----------

    @Test
    void register_success_savesEncodedUserAndReturnsConfirmation() {
        RegisterRequest request = validRequest();
        stubUniquenessChecksPass();
        User saved = savedUserWithId("String123@");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User toSave = invocation.getArgument(0);
            assertThat(toSave.getClientApplicationId()).isEqualTo(CLIENT_APP_ID);
            assertThat(toSave.getUsername()).isEqualTo("newuser");
            assertThat(toSave.getPhoneNumber()).isEqualTo("+23480000000");
            assertThat(toSave.getEmail()).isEqualTo("new@user.com");
            assertThat(toSave.getPassword()).isEqualTo("hashed");
            return saved;
        });
        when(userService.addUserToDefaultPermissionGroup("newuser")).thenReturn(new BaseResponse(201));

        RegisterResponse response = service.register(request, CLIENT_APP_ID);

        assertThat(response.getInternalAuthUserId()).isEqualTo("String123@");
        assertThat(response.getUsername()).isEqualTo("newuser");
        assertThat(response.getMessage()).isEqualTo("Account created successfully.");
    }

    @Test
    void register_success_sendsBothEmailAndPhoneVerificationForTheSavedUser() {
        RegisterRequest request = validRequest();
        stubUniquenessChecksPass();
        User saved = savedUserWithId("String123@");
        when(userRepository.save(any(User.class))).thenReturn(saved);
        when(userService.addUserToDefaultPermissionGroup("newuser")).thenReturn(new BaseResponse(201));

        service.register(request, CLIENT_APP_ID);

        verify(emailVerificationService).sendVerificationEmail(saved);
        verify(phoneVerificationService).sendVerificationOtp(saved);
    }

    @Test
    void register_currentBehavior_neverEnrollsUserIntoDefaultPermissionGroup() {
        RegisterRequest request = validRequest();
        stubUniquenessChecksPass();
        User saved = savedUserWithId("String123@");
        when(userRepository.save(any(User.class))).thenReturn(saved);
        when(userService.addUserToDefaultPermissionGroup("newuser")).thenReturn(new BaseResponse(201));

        service.register(request, CLIENT_APP_ID);

        // Current behavior: register() never calls
        // UserService.addUserToDefaultPermissionGroup, even though the
        // field is wired in - the default-role enrollment described in
        // the class Javadoc isn't actually invoked yet.
        verify(userService, never()).addUserToDefaultPermissionGroup("newuser");
    }

    @Test
    void register_currentBehavior_defaultRoleAssignmentFailureIsSoftFailAndNeverThrows() {
        RegisterRequest request = validRequest();
        stubUniquenessChecksPass();
        User saved = savedUserWithId("String123@");
        when(userRepository.save(any(User.class))).thenReturn(saved);
        when(userService.addUserToDefaultPermissionGroup("newuser")).thenReturn(new BaseResponse(500, "boom"));

        RegisterResponse response = service.register(request, CLIENT_APP_ID);

        assertThat(response.getInternalAuthUserId()).isEqualTo("String123@");
    }

    @Test
    void register_currentBehavior_neverTouchesTransactionSynchronizationManager() {
        RegisterRequest request = validRequest();
        stubUniquenessChecksPass();
        User saved = savedUserWithId("String123@");
        when(userRepository.save(any(User.class))).thenReturn(saved);
        when(userService.addUserToDefaultPermissionGroup("newuser"))
                .thenThrow(new org.springframework.transaction.UnexpectedRollbackException("rollback-only"));

        RegisterResponse response;
        try (MockedStatic<TransactionSynchronizationManager> tsm = mockStatic(TransactionSynchronizationManager.class)) {
            response = service.register(request, CLIENT_APP_ID);

            // Current behavior: register() never registers a synchronization
            // and never calls addUserToDefaultPermissionGroup, so the
            // stubbed-to-throw mock above is never exercised.
            tsm.verifyNoInteractions();
        }
        verify(userService, never()).addUserToDefaultPermissionGroup("newuser");
        assertThat(response.getInternalAuthUserId()).isEqualTo("String123@");
    }

    // -- uniqueness-race handling ----------------------------------------------

    @Test
    void register_currentBehavior_saveRaceLossIsWrappedAsUserAlreadyExistsAndSkipsPostSaveSteps() {
        // The uniqueness pre-checks above are check-then-act, not atomic;
        // save() is the defensive backstop for a race that slips past them.
        RegisterRequest request = validRequest();
        stubUniquenessChecksPass();
        when(userRepository.save(any(User.class))).thenThrow(new DataIntegrityViolationException("duplicate key"));

        assertThatThrownBy(() -> service.register(request, CLIENT_APP_ID))
                .isInstanceOfSatisfying(UserAlreadyExistsException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("Unable to create account with the provided details"));

        verifyNoInteractions(emailVerificationService, phoneVerificationService, userService);
    }
}

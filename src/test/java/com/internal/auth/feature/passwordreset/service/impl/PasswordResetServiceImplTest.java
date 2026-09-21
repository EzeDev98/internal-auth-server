package com.internal.auth.feature.passwordreset.service.impl;

import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.common.exception.OtpInvalidException;
import com.internal.auth.common.exception.OtpResendCooldownException;
import com.internal.auth.common.exception.ResetTokenInvalidException;
import com.internal.auth.common.exception.UserNotFoundException;
import com.internal.auth.common.email.EmailDeliveryService;
import com.internal.auth.common.reset.OtpResetEngine;
import com.internal.auth.common.reset.OtpService;
import com.internal.auth.common.reset.ResetValidator;
import com.internal.auth.common.reset.delivery.OtpDeliveryService;
import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.common.reset.dto.VerifyOtpResponse;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.passwordreset.config.PasswordResetProperties;
import com.internal.auth.feature.passwordreset.dto.request.CompletePasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.request.PasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.response.PasswordResetResponse;
import com.internal.auth.common.reset.ResetStatus;
import com.internal.auth.feature.passwordreset.model.PasswordResetOtp;
import com.internal.auth.feature.passwordreset.model.PasswordResetToken;
import com.internal.auth.feature.passwordreset.repository.PasswordResetOtpRepository;
import com.internal.auth.feature.passwordreset.repository.PasswordResetTokenRepository;
import com.internal.auth.feature.session.service.SessionManagementService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

import static com.internal.auth.common.constant.AppConstant.GENERIC_REQUEST_MESSAGE;
import static com.internal.auth.common.constant.AppConstant.PASSWORD_RESET_COOLDOWN_KEY_PREFIX;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PasswordResetServiceImpl}.
 *
 * PasswordResetProperties is used as a real object (default field values
 * from PasswordOtp/PasswordToken: otp length 6, expiration 5 minutes, max
 * attempts 5, resend cooldown 60 seconds; token expiration 10 minutes)
 * rather than mocked, since it is a plain configuration holder, consistent
 * with how the other identity-area tests in this suite treat
 * @ConfigurationProperties classes.
 */
@ExtendWith(MockitoExtension.class)
class PasswordResetServiceImplTest {

    private static final Long CLIENT_APPLICATION_ID = 1L;
    private static final String PHONE_NUMBER = "+23480123456";
    private static final String RAW_OTP = "482913";
    private static final String RAW_RESET_TOKEN = "raw-reset-token";
    private static final String TOKEN_HASH = "hashed-reset-token";

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordResetOtpRepository passwordResetOtpRepository;
    @Mock
    private PasswordResetTokenRepository passwordResetTokenRepository;
    @Mock
    private OtpService otpService;
    @Mock
    private OtpDeliveryService otpDeliveryService;
    @Mock
    private SessionManagementService sessionManagementService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private ResetValidator resetValidator;
    @Mock
    private RedissonClient redissonClient;
    @Mock
    private OtpResetEngine otpResetEngine;
    @Mock
    private ClientApplicationService clientApplicationService;
    @Mock
    private EmailDeliveryService emailDeliveryService;
    @Mock
    private RBucket<String> cooldownBucket;

    private PasswordResetProperties properties;
    private PasswordResetServiceImpl passwordResetService;

    @BeforeEach
    void setUp() {
        properties = new PasswordResetProperties();
        passwordResetService = new PasswordResetServiceImpl(
                userRepository,
                passwordResetOtpRepository,
                passwordResetTokenRepository,
                otpService,
                otpDeliveryService,
                sessionManagementService,
                passwordEncoder,
                properties,
                resetValidator,
                redissonClient,
                otpResetEngine,
                clientApplicationService,
                emailDeliveryService);

        lenient().when(otpResetEngine.getCooldownBucket(eq(redissonClient), eq(PASSWORD_RESET_COOLDOWN_KEY_PREFIX), anyString()))
                .thenReturn(cooldownBucket);
    }

    private User buildUser() {
        User user = new User();
        user.setId(100L);
        user.setClientApplicationId(CLIENT_APPLICATION_ID);
        user.setPhoneNumber(PHONE_NUMBER);
        return user;
    }

    private PasswordResetOtp buildActiveOtp() {
        PasswordResetOtp otp = new PasswordResetOtp();
        otp.setId(5L);
        otp.setUserId(100L);
        otp.setClientApplicationId(CLIENT_APPLICATION_ID);
        otp.setPhoneNumber(PHONE_NUMBER);
        otp.setStatus(ResetStatus.ACTIVE);
        return otp;
    }

    private PasswordResetToken buildResetToken() {
        PasswordResetToken token = new PasswordResetToken();
        token.setId(9L);
        token.setUserId(100L);
        token.setTokenHash(TOKEN_HASH);
        token.setUsed(false);
        token.setExpiresAt(LocalDateTime.now().plusMinutes(10));
        return token;
    }

    // ---------------------------------------------------------------
    // requestOtp
    // ---------------------------------------------------------------

    @Test
    @DisplayName("requestOtp: invalid phone number throws and never reaches the cooldown check")
    void requestOtp_invalidPhoneNumber_throwsAndSkipsCooldownCheck() {
        PasswordResetRequest request = new PasswordResetRequest("not-a-phone");
        doThrow(new BadRequestException("Please enter a valid phone number"))
                .when(resetValidator).validatePhoneNumberFoResetOperations("not-a-phone");

        assertThrows(BadRequestException.class, () -> passwordResetService.requestOtp(request, CLIENT_APPLICATION_ID));

        verifyNoInteractions(redissonClient, otpResetEngine, userRepository, passwordResetOtpRepository);
    }

    @Test
    @DisplayName("requestOtp: cooling down throws and never reaches the user lookup")
    void requestOtp_coolingDown_throwsAndSkipsUserLookup() {
        PasswordResetRequest request = new PasswordResetRequest(PHONE_NUMBER);
        doThrow(new OtpResendCooldownException("Please wait before requesting another code.", 30L))
                .when(otpResetEngine).rejectIfCoolingDown(cooldownBucket);

        assertThrows(OtpResendCooldownException.class, () -> passwordResetService.requestOtp(request, CLIENT_APPLICATION_ID));

        verifyNoInteractions(userRepository, passwordResetOtpRepository, otpDeliveryService);
        verify(otpResetEngine, never()).startCooldown(any(), anyInt());
    }

    @Test
    @DisplayName("requestOtp: composes the cooldown key as clientApplicationId:phoneNumber, unscoped by trim")
    void requestOtp_composesMultiTenantCooldownKey() {
        PasswordResetRequest request = new PasswordResetRequest(PHONE_NUMBER);
        when(userRepository.findByPhoneNumberAndClientApplicationId(PHONE_NUMBER, CLIENT_APPLICATION_ID))
                .thenReturn(Optional.empty());

        passwordResetService.requestOtp(request, CLIENT_APPLICATION_ID);

        // Unlike EmailVerificationServiceImpl/PhoneVerificationServiceImpl's
        // resendVerification (Step 7 Part D), this method never trims the
        // phone number anywhere, so the cooldown key and the repository
        // lookup both use the exact same raw value.
        verify(otpResetEngine).getCooldownBucket(redissonClient, PASSWORD_RESET_COOLDOWN_KEY_PREFIX, CLIENT_APPLICATION_ID + ":" + PHONE_NUMBER);
    }

    @Test
    @DisplayName("requestOtp: registered phone number invalidates the prior OTP, issues and sends a new one, and returns the generic response")
    void requestOtp_registeredPhoneNumber_issuesOtpAndReturnsGenericResponse() {
        PasswordResetRequest request = new PasswordResetRequest(PHONE_NUMBER);
        User user = buildUser();
        Optional<PasswordResetOtp> existingOtp = Optional.of(buildActiveOtp());
        ClientApplication clientApplication = new ClientApplication();
        clientApplication.setName("SyncPoint");

        when(userRepository.findByPhoneNumberAndClientApplicationId(PHONE_NUMBER, CLIENT_APPLICATION_ID))
                .thenReturn(Optional.of(user));
        when(passwordResetOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
                PHONE_NUMBER, CLIENT_APPLICATION_ID, ResetStatus.ACTIVE))
                .thenReturn(existingOtp);
        when(otpService.generateOtp(6)).thenReturn(RAW_OTP);
        when(clientApplicationService.getById(CLIENT_APPLICATION_ID)).thenReturn(clientApplication);

        PasswordResetResponse response = passwordResetService.requestOtp(request, CLIENT_APPLICATION_ID);

        verify(otpResetEngine).invalidateExisting(eq(existingOtp), any());
        verify(otpResetEngine).populateNewOtp(any(PasswordResetOtp.class), eq(PHONE_NUMBER), eq(RAW_OTP), eq(5), eq(5));

        ArgumentCaptor<PasswordResetOtp> savedOtpCaptor = ArgumentCaptor.forClass(PasswordResetOtp.class);
        verify(passwordResetOtpRepository).save(savedOtpCaptor.capture());
        assertThat(savedOtpCaptor.getValue().getUserId()).isEqualTo(100L);
        assertThat(savedOtpCaptor.getValue().getClientApplicationId()).isEqualTo(CLIENT_APPLICATION_ID);

        verify(otpDeliveryService).sendPasswordResetOtp(PHONE_NUMBER, RAW_OTP, "SyncPoint");
        verify(otpResetEngine).startCooldown(cooldownBucket, 60);

        assertThat(response.getMessage()).isEqualTo(GENERIC_REQUEST_MESSAGE);
        assertThat(response.getStatusCode()).isEqualTo(200);
    }

    @Test
    @DisplayName("requestOtp: unregistered phone number still starts the cooldown and returns the same generic response, without issuing an OTP")
    void requestOtp_unregisteredPhoneNumber_returnsGenericResponseWithoutIssuingOtp() {
        PasswordResetRequest request = new PasswordResetRequest(PHONE_NUMBER);
        when(userRepository.findByPhoneNumberAndClientApplicationId(PHONE_NUMBER, CLIENT_APPLICATION_ID))
                .thenReturn(Optional.empty());

        PasswordResetResponse response = passwordResetService.requestOtp(request, CLIENT_APPLICATION_ID);

        verifyNoInteractions(passwordResetOtpRepository, otpDeliveryService);
        // Explicit type witnesses: both arguments are bare any() matchers
        // here, giving the compiler no concrete-type evidence to infer T
        // from (unlike the "success" test above, where any(X.class) or a
        // concretely-typed eq(...) pins it down).
        verify(otpResetEngine, never()).<PasswordResetOtp>invalidateExisting(any(), any());
        verify(otpResetEngine, never()).<PasswordResetOtp>populateNewOtp(any(), anyString(), anyString(), anyInt(), anyInt());
        verify(otpResetEngine).startCooldown(cooldownBucket, 60);

        assertThat(response.getMessage()).isEqualTo(GENERIC_REQUEST_MESSAGE);
        assertThat(response.getStatusCode()).isEqualTo(200);
    }

    @Test
    @DisplayName("requestOtp: never falls back to the unscoped repository lookup")
    void requestOtp_neverUsesUnscopedRepositoryLookup() {
        PasswordResetRequest request = new PasswordResetRequest(PHONE_NUMBER);
        when(userRepository.findByPhoneNumberAndClientApplicationId(PHONE_NUMBER, CLIENT_APPLICATION_ID))
                .thenReturn(Optional.of(buildUser()));
        when(passwordResetOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
                PHONE_NUMBER, CLIENT_APPLICATION_ID, ResetStatus.ACTIVE))
                .thenReturn(Optional.empty());
        when(otpService.generateOtp(6)).thenReturn(RAW_OTP);
        when(clientApplicationService.getById(CLIENT_APPLICATION_ID)).thenReturn(new ClientApplication());

        passwordResetService.requestOtp(request, CLIENT_APPLICATION_ID);

        verify(passwordResetOtpRepository, never())
                .findTopByPhoneNumberAndStatusOrderByCreatedAtDesc(any(), any());
    }

    // ---------------------------------------------------------------
    // verifyOtp
    // ---------------------------------------------------------------

    @Test
    @DisplayName("verifyOtp: invalid phone number throws and never validates the OTP format")
    void verifyOtp_invalidPhoneNumber_throwsAndSkipsOtpFormatCheck() {
        VerifyOtpRequest request = new VerifyOtpRequest("bad-phone", "123456");
        doThrow(new BadRequestException("Please enter a valid phone number"))
                .when(resetValidator).validatePhoneNumberFoResetOperations("bad-phone");

        assertThrows(BadRequestException.class, () -> passwordResetService.verifyOtp(request, CLIENT_APPLICATION_ID));

        verify(resetValidator, never()).validateOtpFormat(anyString(), anyInt());
        verifyNoInteractions(passwordResetOtpRepository);
    }

    @Test
    @DisplayName("verifyOtp: validates phone number before OTP format")
    void verifyOtp_validatesPhoneBeforeOtpFormat() {
        VerifyOtpRequest request = new VerifyOtpRequest(PHONE_NUMBER, "123456");
        when(passwordResetOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
                PHONE_NUMBER, CLIENT_APPLICATION_ID, ResetStatus.ACTIVE))
                .thenReturn(Optional.of(buildActiveOtp()));
        when(otpService.generateResetToken()).thenReturn(RAW_RESET_TOKEN);

        passwordResetService.verifyOtp(request, CLIENT_APPLICATION_ID);

        InOrder inOrder = org.mockito.Mockito.inOrder(resetValidator);
        inOrder.verify(resetValidator).validatePhoneNumberFoResetOperations(PHONE_NUMBER);
        inOrder.verify(resetValidator).validateOtpFormat("123456", 6);
    }

    @Test
    @DisplayName("verifyOtp: no active OTP for the phone number throws OtpInvalidException")
    void verifyOtp_noActiveOtp_throwsOtpInvalidException() {
        VerifyOtpRequest request = new VerifyOtpRequest(PHONE_NUMBER, "123456");
        when(passwordResetOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
                PHONE_NUMBER, CLIENT_APPLICATION_ID, ResetStatus.ACTIVE))
                .thenReturn(Optional.empty());

        assertThrows(OtpInvalidException.class, () -> passwordResetService.verifyOtp(request, CLIENT_APPLICATION_ID));

        verifyNoInteractions(otpResetEngine);
        verifyNoInteractions(passwordResetTokenRepository);
    }

    @Test
    @DisplayName("verifyOtp: propagates rejection from otpResetEngine.verify without issuing a token")
    void verifyOtp_engineRejection_propagatesAndSkipsTokenIssuance() {
        VerifyOtpRequest request = new VerifyOtpRequest(PHONE_NUMBER, "000000");
        PasswordResetOtp otpEntity = buildActiveOtp();
        when(passwordResetOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
                PHONE_NUMBER, CLIENT_APPLICATION_ID, ResetStatus.ACTIVE))
                .thenReturn(Optional.of(otpEntity));
        doThrow(new OtpInvalidException("The verification code is invalid."))
                .when(otpResetEngine).verify(eq(otpEntity), eq("000000"), any());

        assertThrows(OtpInvalidException.class, () -> passwordResetService.verifyOtp(request, CLIENT_APPLICATION_ID));

        verifyNoInteractions(passwordResetTokenRepository);
        verify(otpService, never()).generateResetToken();
    }

    @Test
    @DisplayName("verifyOtp: success issues and saves a reset token scoped to the OTP's user, returned in the response")
    void verifyOtp_success_issuesResetToken() {
        VerifyOtpRequest request = new VerifyOtpRequest(PHONE_NUMBER, "482913");
        PasswordResetOtp otpEntity = buildActiveOtp();
        when(passwordResetOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
                PHONE_NUMBER, CLIENT_APPLICATION_ID, ResetStatus.ACTIVE))
                .thenReturn(Optional.of(otpEntity));
        when(otpService.generateResetToken()).thenReturn(RAW_RESET_TOKEN);

        VerifyOtpResponse response = passwordResetService.verifyOtp(request, CLIENT_APPLICATION_ID);

        verify(otpResetEngine).verify(eq(otpEntity), eq("482913"), any());
        verify(otpResetEngine).populateNewToken(any(PasswordResetToken.class), eq(RAW_RESET_TOKEN), eq(10));

        ArgumentCaptor<PasswordResetToken> savedTokenCaptor = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(passwordResetTokenRepository).save(savedTokenCaptor.capture());
        assertThat(savedTokenCaptor.getValue().getUserId()).isEqualTo(otpEntity.getUserId());

        assertThat(response.getResetToken()).isEqualTo(RAW_RESET_TOKEN);
    }

    // ---------------------------------------------------------------
    // completeReset
    // ---------------------------------------------------------------

    @Test
    @DisplayName("completeReset: validates the new password before checking whether a reset token was even supplied")
    void completeReset_validatesNewPasswordBeforeResetTokenPresence() {
        CompletePasswordResetRequest request = new CompletePasswordResetRequest(null, "short", "short");
        doThrow(new BadRequestException("Password must be at least 8 characters"))
                .when(resetValidator).validateNewPassword("short", "short");

        BadRequestException thrown = assertThrows(BadRequestException.class,
                () -> passwordResetService.completeReset(request));

        assertThat(thrown.getMessage()).isEqualTo("Password must be at least 8 characters");
        verifyNoInteractions(passwordResetTokenRepository, otpResetEngine, userRepository);
    }

    @Test
    @DisplayName("completeReset: null reset token throws ResetTokenInvalidException once the password passes validation")
    void completeReset_nullResetToken_throwsResetTokenInvalidException() {
        CompletePasswordResetRequest request = new CompletePasswordResetRequest(null, "newPassword1", "newPassword1");

        assertThrows(ResetTokenInvalidException.class, () -> passwordResetService.completeReset(request));

        verifyNoInteractions(passwordResetTokenRepository, otpService);
    }

    @Test
    @DisplayName("completeReset: blank reset token throws ResetTokenInvalidException")
    void completeReset_blankResetToken_throwsResetTokenInvalidException() {
        CompletePasswordResetRequest request = new CompletePasswordResetRequest("   ", "newPassword1", "newPassword1");

        assertThrows(ResetTokenInvalidException.class, () -> passwordResetService.completeReset(request));

        verifyNoInteractions(passwordResetTokenRepository, otpService);
    }

    @Test
    @DisplayName("completeReset: unknown token hash throws ResetTokenInvalidException")
    void completeReset_unknownTokenHash_throwsResetTokenInvalidException() {
        CompletePasswordResetRequest request = new CompletePasswordResetRequest(RAW_RESET_TOKEN, "newPassword1", "newPassword1");
        when(otpService.hashResetToken(RAW_RESET_TOKEN)).thenReturn(TOKEN_HASH);
        when(passwordResetTokenRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.empty());

        assertThrows(ResetTokenInvalidException.class, () -> passwordResetService.completeReset(request));

        verifyNoInteractions(otpResetEngine, userRepository);
    }

    @Test
    @DisplayName("completeReset: propagates rejection from otpResetEngine.assertUsable without looking up the user")
    void completeReset_tokenNotUsable_propagatesAndSkipsUserLookup() {
        CompletePasswordResetRequest request = new CompletePasswordResetRequest(RAW_RESET_TOKEN, "newPassword1", "newPassword1");
        PasswordResetToken token = buildResetToken();
        when(otpService.hashResetToken(RAW_RESET_TOKEN)).thenReturn(TOKEN_HASH);
        when(passwordResetTokenRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
        doThrow(new ResetTokenInvalidException("Your password reset session has expired. Please start again."))
                .when(otpResetEngine).assertUsable(token, "Your password reset session has expired. Please start again.");

        assertThrows(ResetTokenInvalidException.class, () -> passwordResetService.completeReset(request));

        verifyNoInteractions(userRepository);
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    @DisplayName("completeReset: token resolves to a missing user throws UserNotFoundException without updating anything")
    void completeReset_userNotFound_throwsUserNotFoundException() {
        CompletePasswordResetRequest request = new CompletePasswordResetRequest(RAW_RESET_TOKEN, "newPassword1", "newPassword1");
        PasswordResetToken token = buildResetToken();
        when(otpService.hashResetToken(RAW_RESET_TOKEN)).thenReturn(TOKEN_HASH);
        when(passwordResetTokenRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
        when(userRepository.findById(token.getUserId())).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> passwordResetService.completeReset(request));

        verify(passwordEncoder, never()).encode(anyString());
        // Type witness for the same reason as above - both args are bare
        // any() matchers with no concrete-type evidence for T.
        verify(otpResetEngine, never()).<PasswordResetToken>markUsed(any(), any());
        verifyNoInteractions(sessionManagementService);
    }

    @Test
    @DisplayName("completeReset: success updates the password, stamps passwordChangedAt, marks the token used, and invalidates the user's session by id (not the admin/username path)")
    void completeReset_success_updatesPasswordAndInvalidatesSession() {
        CompletePasswordResetRequest request = new CompletePasswordResetRequest(RAW_RESET_TOKEN, "newPassword1", "newPassword1");
        PasswordResetToken token = buildResetToken();
        User user = buildUser();
        when(otpService.hashResetToken(RAW_RESET_TOKEN)).thenReturn(TOKEN_HASH);
        when(passwordResetTokenRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
        when(userRepository.findById(token.getUserId())).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("newPassword1")).thenReturn("encoded-password");

        PasswordResetResponse response = passwordResetService.completeReset(request);

        ArgumentCaptor<User> savedUserCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(savedUserCaptor.capture());
        assertThat(savedUserCaptor.getValue().getPassword()).isEqualTo("encoded-password");
        assertThat(savedUserCaptor.getValue().getPasswordChangedAt()).isNotNull();

        verify(otpResetEngine).markUsed(eq(token), any());
        verify(sessionManagementService).invalidateActiveSessionForUser(user.getId());
        verify(sessionManagementService, never()).invalidateUserSessionByAdmin(anyString(), any());

        assertThat(response.getMessage()).isEqualTo("Password reset successful. Please log in with your new password.");
        assertThat(response.getStatusCode()).isEqualTo(200);
    }
}

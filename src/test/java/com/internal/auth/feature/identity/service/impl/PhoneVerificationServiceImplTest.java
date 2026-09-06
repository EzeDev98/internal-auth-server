package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.common.exception.OtpInvalidException;
import com.internal.auth.common.exception.OtpResendCooldownException;
import com.internal.auth.common.exception.UserNotFoundException;
import com.internal.auth.common.reset.OtpResetEngine;
import com.internal.auth.common.reset.OtpService;
import com.internal.auth.common.reset.ResetValidator;
import com.internal.auth.common.reset.delivery.OtpDeliveryService;
import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.config.PhoneVerificationProperties;
import com.internal.auth.feature.identity.dto.ActivationResponse;
import com.internal.auth.feature.identity.model.PhoneVerificationOtp;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.PhoneVerificationOtpRepository;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.common.reset.ResetStatus;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class PhoneVerificationServiceImplTest {

    private static final Long CLIENT_APP_ID = 7L;
    private static final String GENERIC_RESEND_MESSAGE =
            "If this phone number is registered and not yet verified, a verification code has been sent.";

    private final UserRepository userRepository = mock(UserRepository.class);
    private final PhoneVerificationOtpRepository phoneVerificationOtpRepository = mock(PhoneVerificationOtpRepository.class);
    private final OtpService otpService = mock(OtpService.class);
    private final OtpDeliveryService otpDeliveryService = mock(OtpDeliveryService.class);
    private final OtpResetEngine otpResetEngine = mock(OtpResetEngine.class);
    private final ResetValidator resetValidator = mock(ResetValidator.class);
    private final PhoneVerificationProperties properties = new PhoneVerificationProperties();
    private final RedissonClient redissonClient = mock(RedissonClient.class);
    private final ClientApplicationService clientApplicationService = mock(ClientApplicationService.class);

    private final PhoneVerificationServiceImpl service = new PhoneVerificationServiceImpl(
            userRepository, phoneVerificationOtpRepository, otpService, otpDeliveryService, otpResetEngine,
            resetValidator, properties, redissonClient, clientApplicationService);

    private static User userWithPhone(String phoneNumber, boolean phoneVerified) {
        User user = new User();
        user.setId(1L);
        user.setClientApplicationId(CLIENT_APP_ID);
        user.setPhoneNumber(phoneNumber);
        user.setPhoneVerified(phoneVerified);
        return user;
    }

    private static ClientApplication clientApplication(String name) {
        ClientApplication app = new ClientApplication();
        app.setName(name);
        return app;
    }

    // ===================== sendVerificationOtp() ====================

    @Test
    void sendVerificationOtp_nullPhoneNumber_noOp() {
        User user = userWithPhone(null, false);

        service.sendVerificationOtp(user);

        verifyNoInteractions(phoneVerificationOtpRepository, otpDeliveryService, otpResetEngine, otpService);
    }

    @Test
    void sendVerificationOtp_blankPhoneNumber_noOp() {
        User user = userWithPhone("   ", false);

        service.sendVerificationOtp(user);

        verifyNoInteractions(phoneVerificationOtpRepository, otpDeliveryService);
    }

    @Test
    void sendVerificationOtp_currentBehavior_alreadyVerifiedPhone_noOpEvenThoughNumberIsPresent() {
        User user = userWithPhone("+23480000000", true);

        service.sendVerificationOtp(user);

        verifyNoInteractions(phoneVerificationOtpRepository, otpDeliveryService, otpResetEngine);
    }

    @Test
    void sendVerificationOtp_success_invalidatesExistingGeneratesAndDeliversNewOtp() {
        User user = userWithPhone("+23480000000", false);
        when(phoneVerificationOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
                "+23480000000", CLIENT_APP_ID, ResetStatus.ACTIVE)).thenReturn(Optional.empty());
        when(otpService.generateOtp(6)).thenReturn("135790");
        when(clientApplicationService.getById(CLIENT_APP_ID)).thenReturn(clientApplication("TestApp"));

        service.sendVerificationOtp(user);

        verify(otpResetEngine).<PhoneVerificationOtp>invalidateExisting(eq(Optional.empty()), any());
        verify(otpResetEngine).populateNewOtp(any(PhoneVerificationOtp.class), eq("+23480000000"), eq("135790"), eq(10), eq(5));
        verify(otpDeliveryService).sendPhoneVerificationOtp("+23480000000", "135790", "TestApp");

        ArgumentCaptor<PhoneVerificationOtp> otpCaptor = ArgumentCaptor.forClass(PhoneVerificationOtp.class);
        verify(phoneVerificationOtpRepository).save(otpCaptor.capture());
        assertThat(otpCaptor.getValue().getUserId()).isEqualTo(1L);
        assertThat(otpCaptor.getValue().getClientApplicationId()).isEqualTo(CLIENT_APP_ID);
    }

    @Test
    void sendVerificationOtp_currentBehavior_deliveryFailureIsSwallowedNotThrown() {
        User user = userWithPhone("+23480000000", false);
        when(phoneVerificationOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
                "+23480000000", CLIENT_APP_ID, ResetStatus.ACTIVE)).thenReturn(Optional.empty());
        when(otpService.generateOtp(6)).thenReturn("135790");
        when(clientApplicationService.getById(CLIENT_APP_ID)).thenReturn(clientApplication("TestApp"));
        doThrow(new RuntimeException("provider outage"))
                .when(otpDeliveryService).sendPhoneVerificationOtp(anyString(), anyString(), anyString());

        assertThatCode(() -> service.sendVerificationOtp(user)).doesNotThrowAnyException();
    }

    // ===================== verify() ====================

    @Test
    void verify_invalidPhoneFormat_propagatesAndNeverTouchesRepository() {
        VerifyOtpRequest request = new VerifyOtpRequest("not-a-phone", "123456");
        doThrow(new BadRequestException("Please enter a valid phone number"))
                .when(resetValidator).validatePhoneNumberFoResetOperations("not-a-phone");

        assertThatThrownBy(() -> service.verify(request, CLIENT_APP_ID))
                .isInstanceOf(BadRequestException.class);

        verifyNoInteractions(phoneVerificationOtpRepository);
    }

    @Test
    void verify_invalidOtpFormat_propagatesAndNeverTouchesRepository() {
        VerifyOtpRequest request = new VerifyOtpRequest("+23480000000", "12");
        doThrow(new BadRequestException("The verification code is invalid"))
                .when(resetValidator).validateOtpFormat("12", 6);

        assertThatThrownBy(() -> service.verify(request, CLIENT_APP_ID))
                .isInstanceOf(BadRequestException.class);

        verifyNoInteractions(phoneVerificationOtpRepository);
    }

    @Test
    void verify_currentBehavior_validatesFormatBeforeLookingUpTheOtp() {
        VerifyOtpRequest request = new VerifyOtpRequest("+23480000000", "654321");
        doThrow(new BadRequestException("Phone number is required"))
                .when(resetValidator).validatePhoneNumberFoResetOperations("+23480000000");

        assertThatThrownBy(() -> service.verify(request, CLIENT_APP_ID)).isInstanceOf(BadRequestException.class);

        verify(resetValidator, never()).validateOtpFormat(anyString(), anyInt());
        verifyNoInteractions(phoneVerificationOtpRepository);
    }

    @Test
    void verify_noActiveOtpForPhoneAndTenant_throwsOtpInvalid() {
        VerifyOtpRequest request = new VerifyOtpRequest("+23480000000", "654321");
        when(phoneVerificationOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
                "+23480000000", CLIENT_APP_ID, ResetStatus.ACTIVE)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.verify(request, CLIENT_APP_ID))
                .isInstanceOfSatisfying(OtpInvalidException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("The verification code is invalid."));
    }

    @Test
    void verify_otpVerificationRejected_propagatesWhateverOtpResetEngineThrows() {
        VerifyOtpRequest request = new VerifyOtpRequest("+23480000000", "000000");
        PhoneVerificationOtp otp = new PhoneVerificationOtp();
        otp.setUserId(1L);
        when(phoneVerificationOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
                "+23480000000", CLIENT_APP_ID, ResetStatus.ACTIVE)).thenReturn(Optional.of(otp));
        doThrow(new OtpInvalidException("The verification code is invalid."))
                .when(otpResetEngine).verify(eq(otp), eq("000000"), any());

        assertThatThrownBy(() -> service.verify(request, CLIENT_APP_ID)).isInstanceOf(OtpInvalidException.class);

        verifyNoInteractions(userRepository);
    }

    @Test
    void verify_verifiedButUserRecordMissing_throwsUserNotFoundException() {
        VerifyOtpRequest request = new VerifyOtpRequest("+23480000000", "654321");
        PhoneVerificationOtp otp = new PhoneVerificationOtp();
        otp.setUserId(99L);
        when(phoneVerificationOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
                "+23480000000", CLIENT_APP_ID, ResetStatus.ACTIVE)).thenReturn(Optional.of(otp));
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.verify(request, CLIENT_APP_ID))
                .isInstanceOfSatisfying(UserNotFoundException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("User not found"));
    }

    @Test
    void verify_success_marksPhoneVerified() {
        VerifyOtpRequest request = new VerifyOtpRequest("+23480000000", "654321");
        PhoneVerificationOtp otp = new PhoneVerificationOtp();
        otp.setUserId(1L);
        User user = userWithPhone("+23480000000", false);
        when(phoneVerificationOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
                "+23480000000", CLIENT_APP_ID, ResetStatus.ACTIVE)).thenReturn(Optional.of(otp));
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        ActivationResponse response = service.verify(request, CLIENT_APP_ID);

        assertThat(response.getMessage()).isEqualTo("Your phone number has been verified.");
        assertThat(user.isPhoneVerified()).isTrue();
        verify(userRepository).save(user);
    }

    // ===================== resendVerification() ====================

    @Test
    void resendVerification_nullPhoneNumber_returnsGenericMessageWithoutAnyLookup() {
        ActivationResponse response = service.resendVerification(null, CLIENT_APP_ID);

        assertThat(response.getMessage()).isEqualTo(GENERIC_RESEND_MESSAGE);
        verifyNoInteractions(otpResetEngine, userRepository);
    }

    @Test
    void resendVerification_blankPhoneNumber_returnsGenericMessageWithoutAnyLookup() {
        ActivationResponse response = service.resendVerification("   ", CLIENT_APP_ID);

        assertThat(response.getMessage()).isEqualTo(GENERIC_RESEND_MESSAGE);
        verifyNoInteractions(otpResetEngine, userRepository);
    }

    @Test
    void resendVerification_coolingDown_propagatesResendCooldownAndNeverLooksUpUser() {
        RBucket<String> bucket = mock(RBucket.class);
        when(otpResetEngine.getCooldownBucket(redissonClient, "phone-verification:resend-cooldown:", CLIENT_APP_ID + ":+23480000000"))
                .thenReturn(bucket);
        doThrow(new OtpResendCooldownException("Please wait before requesting another code.", 30L))
                .when(otpResetEngine).rejectIfCoolingDown(bucket);

        assertThatThrownBy(() -> service.resendVerification("+23480000000", CLIENT_APP_ID))
                .isInstanceOf(OtpResendCooldownException.class);

        verifyNoInteractions(userRepository);
    }

    @Test
    void resendVerification_currentBehavior_lookupIsScopedByClientApplicationId() {
        when(userRepository.findByPhoneNumberAndClientApplicationId("+23480000000", CLIENT_APP_ID)).thenReturn(Optional.empty());

        service.resendVerification("+23480000000", CLIENT_APP_ID);

        verify(userRepository, never()).findByPhoneNumber(anyString());
    }

    @Test
    void resendVerification_currentBehavior_cooldownKeyUsesRawPhoneButLookupUsesTrimmedPhone() {
        when(userRepository.findByPhoneNumberAndClientApplicationId("+23480000000", CLIENT_APP_ID)).thenReturn(Optional.empty());

        service.resendVerification("  +23480000000", CLIENT_APP_ID);

        verify(otpResetEngine).getCooldownBucket(redissonClient, "phone-verification:resend-cooldown:",
                CLIENT_APP_ID + ":  +23480000000");
        verify(userRepository).findByPhoneNumberAndClientApplicationId("+23480000000", CLIENT_APP_ID);
    }

    @Test
    void resendVerification_userAlreadyVerified_doesNotResendButStillStartsCooldown() {
        RBucket<String> bucket = mock(RBucket.class);
        when(otpResetEngine.getCooldownBucket(redissonClient, "phone-verification:resend-cooldown:", CLIENT_APP_ID + ":+23480000000"))
                .thenReturn(bucket);
        when(userRepository.findByPhoneNumberAndClientApplicationId("+23480000000", CLIENT_APP_ID))
                .thenReturn(Optional.of(userWithPhone("+23480000000", true)));

        ActivationResponse response = service.resendVerification("+23480000000", CLIENT_APP_ID);

        assertThat(response.getMessage()).isEqualTo(GENERIC_RESEND_MESSAGE);
        verifyNoInteractions(otpDeliveryService);
        verify(otpResetEngine).startCooldown(bucket, 60);
    }

    @Test
    void resendVerification_currentBehavior_unknownPhoneNumber_stillStartsCooldownAndReturnsGenericMessage() {
        RBucket<String> bucket = mock(RBucket.class);
        when(otpResetEngine.getCooldownBucket(redissonClient, "phone-verification:resend-cooldown:", CLIENT_APP_ID + ":+23480000001"))
                .thenReturn(bucket);
        when(userRepository.findByPhoneNumberAndClientApplicationId("+23480000001", CLIENT_APP_ID)).thenReturn(Optional.empty());

        ActivationResponse response = service.resendVerification("+23480000001", CLIENT_APP_ID);

        assertThat(response.getMessage()).isEqualTo(GENERIC_RESEND_MESSAGE);
        verifyNoInteractions(otpDeliveryService);
        verify(otpResetEngine).startCooldown(bucket, 60);
    }

    @Test
    void resendVerification_success_sendsANewOtpToTheUnverifiedUser() {
        when(userRepository.findByPhoneNumberAndClientApplicationId("+23480000000", CLIENT_APP_ID))
                .thenReturn(Optional.of(userWithPhone("+23480000000", false)));
        when(phoneVerificationOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
                "+23480000000", CLIENT_APP_ID, ResetStatus.ACTIVE)).thenReturn(Optional.empty());
        when(otpService.generateOtp(6)).thenReturn("246810");
        when(clientApplicationService.getById(CLIENT_APP_ID)).thenReturn(clientApplication("TestApp"));

        ActivationResponse response = service.resendVerification("+23480000000", CLIENT_APP_ID);

        assertThat(response.getMessage()).isEqualTo(GENERIC_RESEND_MESSAGE);
        verify(otpDeliveryService).sendPhoneVerificationOtp("+23480000000", "246810", "TestApp");
    }
}

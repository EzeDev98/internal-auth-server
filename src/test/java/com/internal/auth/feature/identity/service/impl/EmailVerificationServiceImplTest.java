//package com.internal.auth.feature.identity.service.impl;
//
//import com.internal.auth.common.crypto.TokenHasher;
//import com.internal.auth.common.email.EmailDeliveryService;
//import com.internal.auth.common.exception.OtpResendCooldownException;
//import com.internal.auth.common.exception.ResetTokenInvalidException;
//import com.internal.auth.common.exception.UserNotFoundException;
//import com.internal.auth.common.reset.OtpResetEngine;
//import com.internal.auth.feature.identity.config.EmailVerificationProperties;
//import com.internal.auth.feature.identity.dto.response.ActivationResponse;
//import com.internal.auth.feature.identity.model.EmailVerificationToken;
//import com.internal.auth.feature.identity.model.User;
//import com.internal.auth.feature.identity.repository.EmailVerificationTokenRepository;
//import com.internal.auth.feature.identity.repository.UserRepository;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.mockito.ArgumentCaptor;
//import org.redisson.api.RBucket;
//import org.redisson.api.RedissonClient;
//import org.springframework.test.util.ReflectionTestUtils;
//
//import java.time.LocalDateTime;
//import java.util.Optional;
//
//import static org.assertj.core.api.Assertions.assertThat;
//import static org.assertj.core.api.Assertions.assertThatCode;
//import static org.assertj.core.api.Assertions.assertThatThrownBy;
//import static org.mockito.ArgumentMatchers.any;
//import static org.mockito.ArgumentMatchers.anyString;
//import static org.mockito.ArgumentMatchers.eq;
//import static org.mockito.Mockito.doThrow;
//import static org.mockito.Mockito.mock;
//import static org.mockito.Mockito.never;
//import static org.mockito.Mockito.verify;
//import static org.mockito.Mockito.verifyNoInteractions;
//import static org.mockito.Mockito.when;
//
//class EmailVerificationServiceImplTest {
//
//    private static final Long CLIENT_APP_ID = 7L;
//    private static final String BASE_URL = "https://auth.example.com";
//    private static final String GENERIC_RESEND_MESSAGE = "A new verification link has been sent.";
//
//    private final UserRepository userRepository = mock(UserRepository.class);
//    private final EmailVerificationTokenRepository tokenRepository = mock(EmailVerificationTokenRepository.class);
//    private final TokenHasher tokenHasher = mock(TokenHasher.class);
//    private final OtpResetEngine otpResetEngine = mock(OtpResetEngine.class);
//    private final EmailDeliveryService emailDeliveryService = mock(EmailDeliveryService.class);
//    private final EmailVerificationProperties properties = new EmailVerificationProperties();
//    private final RedissonClient redissonClient = mock(RedissonClient.class);
//
//    private final EmailVerificationServiceImpl service = new EmailVerificationServiceImpl(
//            userRepository, tokenRepository, tokenHasher, otpResetEngine, emailDeliveryService, properties, redissonClient);
//
//    @BeforeEach
//    void wireBaseUrl() {
//        ReflectionTestUtils.setField(service, "baseUrl", BASE_URL);
//    }
//
//    private static User userWithEmail(String email, boolean emailVerified) {
//        User user = new User();
//        user.setId(1L);
//        user.setClientApplicationId(CLIENT_APP_ID);
//        user.setEmail(email);
//        user.setEmailVerified(emailVerified);
//        return user;
//    }
//
//    // ===================== sendVerificationEmail() ====================
//
//    @Test
//    void sendVerificationEmail_nullEmail_noOp() {
//        User user = userWithEmail(null, false);
//
//        service.sendVerificationEmail(user);
//
//        verifyNoInteractions(tokenRepository, emailDeliveryService, otpResetEngine);
//    }
//
//    @Test
//    void sendVerificationEmail_blankEmail_noOp() {
//        User user = userWithEmail("   ", false);
//
//        service.sendVerificationEmail(user);
//
//        verifyNoInteractions(tokenRepository, emailDeliveryService, otpResetEngine);
//    }
//
//    @Test
//    void sendVerificationEmail_success_populatesTokenAndSendsActivationLink() {
//        User user = userWithEmail("alice@example.com", false);
//
//        service.sendVerificationEmail(user);
//
//        verify(otpResetEngine).populateNewToken(any(EmailVerificationToken.class), anyString(), eq(1440));
//
//        ArgumentCaptor<EmailVerificationToken> tokenCaptor = ArgumentCaptor.forClass(EmailVerificationToken.class);
//        verify(tokenRepository).save(tokenCaptor.capture());
//        assertThat(tokenCaptor.getValue().getUserId()).isEqualTo(1L);
//
//        ArgumentCaptor<String> linkCaptor = ArgumentCaptor.forClass(String.class);
//        verify(emailDeliveryService).sendVerificationEmail(eq("alice@example.com"), linkCaptor.capture());
//        assertThat(linkCaptor.getValue()).startsWith(BASE_URL + "/api/v1/auth/activate?token=");
//    }
//
//    @Test
//    void sendVerificationEmail_currentBehavior_deliveryFailureIsSwallowedNotThrown() {
//        User user = userWithEmail("alice@example.com", false);
//        doThrow(new RuntimeException("provider outage")).when(emailDeliveryService).sendVerificationEmail(anyString(), anyString());
//
//        assertThatCode(() -> service.sendVerificationEmail(user)).doesNotThrowAnyException();
//    }
//
//    @Test
//    void sendVerificationEmail_currentBehavior_tokenSaveFailureIsSwallowedAndNeverAttemptsDelivery() {
//        User user = userWithEmail("alice@example.com", false);
//        doThrow(new RuntimeException("db down")).when(tokenRepository).save(any(EmailVerificationToken.class));
//
//        assertThatCode(() -> service.sendVerificationEmail(user)).doesNotThrowAnyException();
//
//        verifyNoInteractions(emailDeliveryService);
//    }
//
//    // ===================== activate() ====================
//
//    @Test
//    void activate_nullToken_throwsResetTokenInvalidWithoutTouchingRepository() {
//        assertThatThrownBy(() -> service.activate(null))
//                .isInstanceOfSatisfying(ResetTokenInvalidException.class,
//                        ex -> assertThat(ex.getMessage()).isEqualTo("This verification link is invalid or has expired."));
//
//        verifyNoInteractions(tokenRepository, tokenHasher);
//    }
//
//    @Test
//    void activate_blankToken_throwsResetTokenInvalid() {
//        assertThatThrownBy(() -> service.activate("   "))
//                .isInstanceOf(ResetTokenInvalidException.class);
//
//        verifyNoInteractions(tokenRepository);
//    }
//
//    @Test
//    void activate_tokenNotFound_throwsResetTokenInvalid() {
//        when(tokenHasher.sha256Hex("raw-token")).thenReturn("hash123");
//        when(tokenRepository.findByTokenHash("hash123")).thenReturn(Optional.empty());
//
//        assertThatThrownBy(() -> service.activate("raw-token"))
//                .isInstanceOfSatisfying(ResetTokenInvalidException.class,
//                        ex -> assertThat(ex.getMessage()).isEqualTo("This verification link is invalid or has expired."));
//    }
//
//    @Test
//    void activate_currentBehavior_alreadyUsedAndUserAlreadyVerified_returnsSuccessIdempotently() {
//        // Step 8 fix: tolerates an email client's link-scanner consuming
//        // the token before the real recipient clicks it.
//        EmailVerificationToken token = new EmailVerificationToken();
//        token.setUserId(1L);
//        token.setUsed(true);
//        when(tokenHasher.sha256Hex("raw-token")).thenReturn("hash123");
//        when(tokenRepository.findByTokenHash("hash123")).thenReturn(Optional.of(token));
//        when(userRepository.findById(1L)).thenReturn(Optional.of(userWithEmail("alice@example.com", true)));
//
//        ActivationResponse response = service.activate("raw-token");
//
//        assertThat(response.getMessage()).isEqualTo("Your email has been verified.");
//        verifyNoInteractions(otpResetEngine);
//        verify(userRepository, never()).save(any());
//    }
//
//    @Test
//    void activate_currentBehavior_alreadyUsedButUserStillUnverified_throwsResetTokenInvalid() {
//        EmailVerificationToken token = new EmailVerificationToken();
//        token.setUserId(1L);
//        token.setUsed(true);
//        when(tokenHasher.sha256Hex("raw-token")).thenReturn("hash123");
//        when(tokenRepository.findByTokenHash("hash123")).thenReturn(Optional.of(token));
//        when(userRepository.findById(1L)).thenReturn(Optional.of(userWithEmail("alice@example.com", false)));
//
//        assertThatThrownBy(() -> service.activate("raw-token"))
//                .isInstanceOfSatisfying(ResetTokenInvalidException.class,
//                        ex -> assertThat(ex.getMessage()).isEqualTo("This verification link is invalid or has expired."));
//    }
//
//    @Test
//    void activate_currentBehavior_alreadyUsedAndUserRecordMissing_throwsResetTokenInvalid() {
//        EmailVerificationToken token = new EmailVerificationToken();
//        token.setUserId(1L);
//        token.setUsed(true);
//        when(tokenHasher.sha256Hex("raw-token")).thenReturn("hash123");
//        when(tokenRepository.findByTokenHash("hash123")).thenReturn(Optional.of(token));
//        when(userRepository.findById(1L)).thenReturn(Optional.empty());
//
//        assertThatThrownBy(() -> service.activate("raw-token"))
//                .isInstanceOf(ResetTokenInvalidException.class);
//    }
//
//    @Test
//    void activate_notUsable_propagatesWhateverOtpResetEngineThrowsAndNeverLooksUpUser() {
//        EmailVerificationToken token = new EmailVerificationToken();
//        token.setUserId(1L);
//        token.setUsed(false);
//        when(tokenHasher.sha256Hex("raw-token")).thenReturn("hash123");
//        when(tokenRepository.findByTokenHash("hash123")).thenReturn(Optional.of(token));
//        doThrow(new ResetTokenInvalidException("This verification link is invalid or has expired."))
//                .when(otpResetEngine).assertUsable(token, "This verification link is invalid or has expired.");
//
//        assertThatThrownBy(() -> service.activate("raw-token"))
//                .isInstanceOf(ResetTokenInvalidException.class);
//
//        verifyNoInteractions(userRepository);
//    }
//
//    @Test
//    void activate_usableButUserRecordMissing_throwsUserNotFoundException() {
//        EmailVerificationToken token = new EmailVerificationToken();
//        token.setUserId(1L);
//        token.setUsed(false);
//        when(tokenHasher.sha256Hex("raw-token")).thenReturn("hash123");
//        when(tokenRepository.findByTokenHash("hash123")).thenReturn(Optional.of(token));
//        when(userRepository.findById(1L)).thenReturn(Optional.empty());
//
//        assertThatThrownBy(() -> service.activate("raw-token"))
//                .isInstanceOfSatisfying(UserNotFoundException.class,
//                        ex -> assertThat(ex.getMessage()).isEqualTo("User not found"));
//    }
//
//    @Test
//    void activate_success_marksEmailVerifiedAndMarksTokenUsed() {
//        EmailVerificationToken token = new EmailVerificationToken();
//        token.setUserId(1L);
//        token.setUsed(false);
//        token.setExpiresAt(LocalDateTime.now().plusHours(1));
//        User user = userWithEmail("alice@example.com", false);
//        when(tokenHasher.sha256Hex("raw-token")).thenReturn("hash123");
//        when(tokenRepository.findByTokenHash("hash123")).thenReturn(Optional.of(token));
//        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
//
//        ActivationResponse response = service.activate("raw-token");
//
//        assertThat(response.getMessage()).isEqualTo("Your email has been verified.");
//        assertThat(user.isEmailVerified()).isTrue();
//        verify(userRepository).save(user);
//        verify(otpResetEngine).markUsed(eq(token), any());
//    }
//
//    // ===================== resendVerification() ====================
//
//    @Test
//    void resendVerification_nullEmail_returnsGenericMessageWithoutAnyLookup() {
//        ActivationResponse response = service.resendVerification(null, CLIENT_APP_ID);
//
//        assertThat(response.getMessage()).isEqualTo(GENERIC_RESEND_MESSAGE);
//        verifyNoInteractions(otpResetEngine, userRepository);
//    }
//
//    @Test
//    void resendVerification_blankEmail_returnsGenericMessageWithoutAnyLookup() {
//        ActivationResponse response = service.resendVerification("   ", CLIENT_APP_ID);
//
//        assertThat(response.getMessage()).isEqualTo(GENERIC_RESEND_MESSAGE);
//        verifyNoInteractions(otpResetEngine, userRepository);
//    }
//
//    @Test
//    void resendVerification_coolingDown_propagatesResendCooldownAndNeverLooksUpUser() {
//        RBucket<String> bucket = mock(RBucket.class);
//        when(otpResetEngine.getCooldownBucket(redissonClient, "email-verification:resend-cooldown:", CLIENT_APP_ID + ":alice@example.com"))
//                .thenReturn(bucket);
//        doThrow(new OtpResendCooldownException("Please wait before requesting another code.", 30L))
//                .when(otpResetEngine).rejectIfCoolingDown(bucket);
//
//        assertThatThrownBy(() -> service.resendVerification("alice@example.com", CLIENT_APP_ID))
//                .isInstanceOf(OtpResendCooldownException.class);
//
//        verifyNoInteractions(userRepository);
//    }
//
//    @Test
//    void resendVerification_currentBehavior_lookupIsScopedByClientApplicationId() {
//        when(userRepository.findByEmailAndClientApplicationId("alice@example.com", CLIENT_APP_ID)).thenReturn(Optional.empty());
//
//        service.resendVerification("alice@example.com", CLIENT_APP_ID);
//
//        verify(userRepository, never()).findByEmail(anyString());
//    }
//
//    @Test
//    void resendVerification_currentBehavior_cooldownKeyUsesRawEmailButLookupUsesTrimmedEmail() {
//        // "  alice@example.com" and "alice@example.com" resolve to the same
//        // user (trimmed lookup) but do NOT share a cooldown bucket (raw key).
//        when(userRepository.findByEmailAndClientApplicationId("alice@example.com", CLIENT_APP_ID)).thenReturn(Optional.empty());
//
//        service.resendVerification("  alice@example.com", CLIENT_APP_ID);
//
//        verify(otpResetEngine).getCooldownBucket(redissonClient, "email-verification:resend-cooldown:",
//                CLIENT_APP_ID + ":  alice@example.com");
//        verify(userRepository).findByEmailAndClientApplicationId("alice@example.com", CLIENT_APP_ID);
//    }
//
//    @Test
//    void resendVerification_userAlreadyVerified_doesNotResendButStillStartsCooldown() {
//        RBucket<String> bucket = mock(RBucket.class);
//        when(otpResetEngine.getCooldownBucket(redissonClient, "email-verification:resend-cooldown:", CLIENT_APP_ID + ":alice@example.com"))
//                .thenReturn(bucket);
//        when(userRepository.findByEmailAndClientApplicationId("alice@example.com", CLIENT_APP_ID))
//                .thenReturn(Optional.of(userWithEmail("alice@example.com", true)));
//
//        ActivationResponse response = service.resendVerification("alice@example.com", CLIENT_APP_ID);
//
//        assertThat(response.getMessage()).isEqualTo(GENERIC_RESEND_MESSAGE);
//        verifyNoInteractions(emailDeliveryService);
//        verify(otpResetEngine).startCooldown(bucket, 60);
//    }
//
//    @Test
//    void resendVerification_currentBehavior_unknownEmail_stillStartsCooldownAndReturnsGenericMessage() {
//        // Enumeration resistance: an unregistered email behaves identically
//        // to a registered-but-already-verified one from the caller's view.
//        RBucket<String> bucket = mock(RBucket.class);
//        when(otpResetEngine.getCooldownBucket(redissonClient, "email-verification:resend-cooldown:", CLIENT_APP_ID + ":nobody@example.com"))
//                .thenReturn(bucket);
//        when(userRepository.findByEmailAndClientApplicationId("nobody@example.com", CLIENT_APP_ID)).thenReturn(Optional.empty());
//
//        ActivationResponse response = service.resendVerification("nobody@example.com", CLIENT_APP_ID);
//
//        assertThat(response.getMessage()).isEqualTo(GENERIC_RESEND_MESSAGE);
//        verifyNoInteractions(emailDeliveryService);
//        verify(otpResetEngine).startCooldown(bucket, 60);
//    }
//
//    @Test
//    void resendVerification_success_sendsANewVerificationEmailToTheUnverifiedUser() {
//        when(userRepository.findByEmailAndClientApplicationId("alice@example.com", CLIENT_APP_ID))
//                .thenReturn(Optional.of(userWithEmail("alice@example.com", false)));
//
//        ActivationResponse response = service.resendVerification("alice@example.com", CLIENT_APP_ID);
//
//        assertThat(response.getMessage()).isEqualTo(GENERIC_RESEND_MESSAGE);
//        verify(emailDeliveryService).sendVerificationEmail(eq("alice@example.com"), anyString());
//    }
//}

package com.internal.auth.feature.identity.controller;

import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.common.response.InternalAuthApiResponse;
import com.internal.auth.common.util.RateLimiterService;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.dto.response.ActivationResponse;
import com.internal.auth.feature.identity.dto.request.ResendPhoneVerificationRequest;
import com.internal.auth.feature.identity.service.PhoneVerificationService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

import static com.internal.auth.common.constant.AppConstant.MAX_PHONE_VERIFICATION_VERIFY_REQUEST;
import static com.internal.auth.common.constant.AppConstant.PHONE_VERIFICATION_VERIFY_RATE_LIMIT_DURATION_HOURS;
import static com.internal.auth.common.constant.AppConstant.PHONE_VERIFICATION_VERIFY_RATE_LIMIT_KEY_PREFIX;

/**
 * Self-service phone verification via SMS OTP (fixes the
 * previously-permanent phone-only-account login gate). Mapped to the
 * literal "/api/v1/auth" base path, not ${app.title}, same reason as
 * RegistrationController - WebSecurityConfig permits these exact
 * hardcoded paths without a bearer token, and a phone-only user hitting
 * this gate by definition has no token yet.
 *
 * Both endpoints require the same HTTP Basic client-credential header
 * RegistrationController/PasswordResetController resolve - a phone number
 * can be ambiguous across client applications (multi-tenant redesign),
 * unlike email verification's /activate which resolves via an unambiguous
 * token hash.
 */
@RestController
@RequestMapping("${app.title}/auth")
@Tag(name = "Phone Verification API", description = "Account phone-number verification via SMS OTP")
@RequiredArgsConstructor
public class PhoneVerificationController {

    private final PhoneVerificationService phoneVerificationService;
    private final ClientApplicationService clientApplicationService;
    private final RateLimiterService rateLimiterService;

    @PostMapping("/verify-phone")
    public ResponseEntity<InternalAuthApiResponse<ActivationResponse>> verifyPhone(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody VerifyOtpRequest request) {
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        // Mirrors PasswordResetController's /verify-otp guard - the OTP's
        // own attemptCount resets on every fresh code request, so this
        // caps guessing independently of how many OTPs were issued.
        rateLimiterService.checkRateLimit(
                PHONE_VERIFICATION_VERIFY_RATE_LIMIT_KEY_PREFIX + client.getId() + ":" + request.getPhoneNumber(),
                MAX_PHONE_VERIFICATION_VERIFY_REQUEST,
                Duration.ofHours(PHONE_VERIFICATION_VERIFY_RATE_LIMIT_DURATION_HOURS));
        ActivationResponse response = phoneVerificationService.verify(request, client.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    @PostMapping("/resend-phone-verification")
    public ResponseEntity<InternalAuthApiResponse<ActivationResponse>> resendPhoneVerification(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody ResendPhoneVerificationRequest request) {
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        ActivationResponse response = phoneVerificationService.resendVerification(request.getPhoneNumber(), client.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }
}

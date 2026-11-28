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

/** Endpoints for verifying a phone number by SMS OTP. */
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

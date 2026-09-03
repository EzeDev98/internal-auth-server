package com.internal.auth.feature.identity.controller;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.dto.LoginRequest;
import com.internal.auth.feature.identity.dto.LoginResponse;
import com.internal.auth.feature.identity.dto.VerifyLoginOtpRequest;
import com.internal.auth.feature.identity.service.LoginService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Step 11A/11E. Same literal "/api/v1/auth" base as RegistrationController.
 * "/login/verify-otp" needed its own new permitAll rule in WebSecurityConfig,
 * same reasoning as "/login" itself - see that file's diff.
 *
 * Multi-tenant redesign: both "/login" and "/login/verify-otp" now
 * require the same HTTP Basic client-credential header
 * RegistrationController resolves (see its Javadoc for the full
 * rationale) - "/login/verify-otp"'s login-MFA OTP lookup is scoped by
 * client_application_id now too (see LoginServiceImpl's class Javadoc).
 */
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Login API", description = "Local credential authentication with optional MFA step-up (Stage 3/4 Steps 11A/11E)")
@RequiredArgsConstructor
public class LoginController {

    private final LoginService loginService;
    private final ClientApplicationService clientApplicationService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody LoginRequest request) {
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        return ResponseEntity.ok(loginService.login(request, client.getId()));
    }

    @PostMapping("/login/verify-otp")
    public ResponseEntity<LoginResponse> verifyLoginOtp(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody VerifyLoginOtpRequest request) {
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        return ResponseEntity.ok(loginService.verifyLoginOtp(request, client.getId()));
    }
}

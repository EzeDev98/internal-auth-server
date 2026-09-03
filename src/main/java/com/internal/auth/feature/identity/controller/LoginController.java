package com.internal.auth.feature.identity.controller;

import com.internal.auth.feature.identity.dto.LoginRequest;
import com.internal.auth.feature.identity.dto.LoginResponse;
import com.internal.auth.feature.identity.dto.VerifyLoginOtpRequest;
import com.internal.auth.feature.identity.service.LoginService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Step 11A/11E. Same literal "/api/v1/auth" base as RegistrationController.
 * "/login/verify-otp" needed its own new permitAll rule in WebSecurityConfig,
 * same reasoning as "/login" itself - see that file's diff.
 */
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Login API", description = "Local credential authentication with optional MFA step-up (Stage 3/4 Steps 11A/11E)")
@RequiredArgsConstructor
public class LoginController {

    private final LoginService loginService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(loginService.login(request));
    }

    @PostMapping("/login/verify-otp")
    public ResponseEntity<LoginResponse> verifyLoginOtp(@RequestBody VerifyLoginOtpRequest request) {
        return ResponseEntity.ok(loginService.verifyLoginOtp(request));
    }
}

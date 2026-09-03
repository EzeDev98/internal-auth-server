package com.internal.auth.feature.identity.controller;

import com.internal.auth.feature.identity.dto.RegisterRequest;
import com.internal.auth.feature.identity.dto.RegisterResponse;
import com.internal.auth.feature.identity.service.RegistrationService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Step 10A. Mapped to the literal "/api/v1/auth" base path - not the
 * ${app.title} convention PasswordResetController/PermissionController use
 * - because WebSecurityConfig already permits POST /api/v1/auth/register
 * without a bearer token at that exact hardcoded path (its
 * securityFilterChain() comment notes this was "confirmed with the project
 * owner"). Using ${app.title} here would silently fall through to
 * .anyRequest().authenticated() and make registration impossible to call
 * without a JWT you can't have yet.
 */
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Registration API", description = "Account creation (Stage 3/4 Step 10A)")
@RequiredArgsConstructor
public class RegistrationController {

    private final RegistrationService registrationService;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@RequestBody RegisterRequest request) {
        RegisterResponse response = registrationService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}

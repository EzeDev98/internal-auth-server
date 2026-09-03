package com.internal.auth.feature.identity.controller;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.dto.RegisterRequest;
import com.internal.auth.feature.identity.dto.RegisterResponse;
import com.internal.auth.feature.identity.service.RegistrationService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
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
 *
 * Multi-tenant redesign, registration step: the caller (SyncPoint, Notare,
 * ...) now identifies itself via HTTP Basic auth (Authorization: Basic
 * base64(clientId:clientSecret)), verified here against the already-built
 * Step 10D admin-registered ClientApplication rows
 * (ClientApplicationService#authenticateClientFromBasicAuthHeader). This is
 * deliberately NOT Spring Security's httpBasic() - WebSecurityConfig has no
 * such filter configured, so the header passes through untouched and is
 * read/verified manually here, the same way LoginServiceImpl checks user
 * passwords manually rather than via an AuthenticationManager. An
 * unrecognized/missing/wrong clientId+clientSecret is rejected outright
 * (401) - it never auto-creates a client application; onboarding a new app
 * stays an admin-only act via POST ${app.title}/client-applications, per
 * your explicit decision.
 */
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Registration API", description = "Account creation (Stage 3/4 Step 10A)")
@RequiredArgsConstructor
public class RegistrationController {

    private final RegistrationService registrationService;
    private final ClientApplicationService clientApplicationService;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody RegisterRequest request) {
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        RegisterResponse response = registrationService.register(request, client.getId());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}

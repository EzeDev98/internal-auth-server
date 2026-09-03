package com.internal.auth.feature.client.controller;

import com.internal.auth.config.auth.Roles;
import com.internal.auth.feature.client.dto.CreateClientApplicationRequest;
import com.internal.auth.feature.client.dto.CreateClientApplicationResponse;
import com.internal.auth.feature.client.service.ClientApplicationService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Step 10D. Unlike RegistrationController/EmailVerificationController
 * (pinned to the literal "/api/v1/auth" path to match WebSecurityConfig's
 * pre-wired permitAll rules), this is an authenticated, admin-only endpoint
 * - there's no permitAll rule for it, so it falls under the default
 * .anyRequest().authenticated(), same as every RBAC endpoint in
 * PermissionController, and uses that same ${app.title} base-path
 * convention and Roles constant rather than a hardcoded path.
 */
@RestController
@RequestMapping("${app.title}/client-applications")
@Tag(name = "Client Application API", description = "Admin registration of client applications (Stage 3/4 Step 10D)")
@RequiredArgsConstructor
public class ClientApplicationController {

    private final ClientApplicationService clientApplicationService;

    @PostMapping
    @PreAuthorize(Roles.HAS_ADMIN)
    public ResponseEntity<CreateClientApplicationResponse> createClient(@RequestBody CreateClientApplicationRequest request) {
        CreateClientApplicationResponse response = clientApplicationService.createClient(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}

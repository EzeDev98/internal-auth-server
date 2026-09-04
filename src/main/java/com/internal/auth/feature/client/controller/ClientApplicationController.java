package com.internal.auth.feature.client.controller;

import com.internal.auth.common.constant.AppConstant;
import com.internal.auth.common.response.InternalAuthApiResponse;
import com.internal.auth.common.util.RateLimiterService;
import com.internal.auth.config.auth.Roles;
import com.internal.auth.feature.client.dto.CreateClientApplicationRequest;
import com.internal.auth.feature.client.dto.CreateClientApplicationResponse;
import com.internal.auth.feature.client.service.ClientApplicationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/**
 * Step 10D. Unlike RegistrationController/EmailVerificationController
 * (pinned to the literal "/api/v1/auth" path to match WebSecurityConfig's
 * pre-wired permitAll rules), this is an authenticated, admin-only endpoint
 * - there's no permitAll rule for it, so it falls under the default
 * .anyRequest().authenticated(), same as every RBAC endpoint in
 * PermissionController, and uses that same ${app.title} base-path
 * convention and Roles constant rather than a hardcoded path.
 *
 * rotateSecret fixes "no client-secret rotation endpoint - you must
 * create a new client application" (CreateClientApplicationResponse's own
 * Javadoc used to document this as a known gap). Rate-limited the same
 * way SigningKeyController's rotation endpoint is: already
 * @PreAuthorize-gated to admins, so this is abuse-prevention against
 * repeatedly triggering a rotation, not brute-force defense.
 */
@RestController
@RequestMapping("${app.title}/client-applications")
@Tag(name = "Client Application API", description = "Admin registration and secret rotation for client applications (Stage 3/4 Step 10D)")
@RequiredArgsConstructor
public class ClientApplicationController {

    private final ClientApplicationService clientApplicationService;
    private final RateLimiterService rateLimiterService;

    @PostMapping
    @PreAuthorize(Roles.HAS_ADMIN)
    public ResponseEntity<InternalAuthApiResponse<CreateClientApplicationResponse>> createClient(@RequestBody CreateClientApplicationRequest request) {
        CreateClientApplicationResponse response = clientApplicationService.createClient(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    @Operation(method = "POST", summary = "Rotate client secret", description = "Generates a new client secret for an existing client application and replaces the stored one immediately. Returned exactly once - save it now.")
    @PreAuthorize(Roles.HAS_ADMIN)
    @PostMapping("/{clientId}/rotate-secret")
    public ResponseEntity<InternalAuthApiResponse<CreateClientApplicationResponse>> rotateSecret(@PathVariable String clientId, HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(AppConstant.CLIENT_SECRET_ROTATE_RATE_LIMIT_KEY_PREFIX + httpRequest.getRemoteAddr(), AppConstant.MAX_CLIENT_SECRET_ROTATE_REQUEST, Duration.ofDays(AppConstant.CLIENT_SECRET_ROTATE_RATE_LIMIT_DURATION_DAYS));
        CreateClientApplicationResponse response = clientApplicationService.rotateClientSecret(clientId);
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }
}

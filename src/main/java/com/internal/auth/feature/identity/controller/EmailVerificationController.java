package com.internal.auth.feature.identity.controller;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.dto.ActivationRequest;
import com.internal.auth.feature.identity.dto.ActivationResponse;
import com.internal.auth.feature.identity.dto.ResendActivationRequest;
import com.internal.auth.feature.identity.service.EmailVerificationService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Step 10C. Same literal "/api/v1/auth" base path as RegistrationController,
 * for the same reason: WebSecurityConfig permits GET and POST
 * /api/v1/auth/activate and POST /api/v1/auth/resend-activation at these
 * exact hardcoded paths without a bearer token - the ${app.title}
 * convention other controllers use would break that.
 *
 * Multi-tenant redesign, OTP/token flows step: "/resend-activation" now
 * requires the same HTTP Basic client-credential header
 * RegistrationController resolves (see its Javadoc for the full
 * rationale) - EmailVerificationService#resendVerification's email lookup
 * is scoped by client_application_id now. "/activate" (both variants) is
 * untouched - it resolves via the token's own hash, which was never
 * ambiguous, so there's no caller identity to resolve there.
 */
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Email Verification API", description = "Account activation via emailed link (Stage 3/4 Step 10C)")
@RequiredArgsConstructor
public class EmailVerificationController {

    private final EmailVerificationService emailVerificationService;
    private final ClientApplicationService clientApplicationService;

    /** For a browser following the emailed link directly. */
    @GetMapping("/activate")
    public ResponseEntity<ActivationResponse> activateViaLink(@RequestParam String token) {
        return ResponseEntity.ok(emailVerificationService.activate(token));
    }

    /** For an API client (e.g. a SPA intercepting the link) submitting the token itself. */
    @PostMapping("/activate")
    public ResponseEntity<ActivationResponse> activateViaApi(@RequestBody ActivationRequest request) {
        return ResponseEntity.ok(emailVerificationService.activate(request.getToken()));
    }

    @PostMapping("/resend-activation")
    public ResponseEntity<ActivationResponse> resendActivation(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody ResendActivationRequest request) {
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        return ResponseEntity.ok(emailVerificationService.resendVerification(request.getEmail(), client.getId()));
    }
}

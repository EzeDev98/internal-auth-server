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

import com.internal.auth.common.response.InternalAuthApiResponse;

/**
 * Step 10C. Mapped under the "${app.title}" property, same base as
 * RegistrationController/LoginController - see RegistrationController's
 * javadoc for why this reverted from a hardcoded "/api/v1/auth" literal
 * back to the property (API-contract review, step 1): WebSecurityConfig now
 * builds its GET/POST "/activate" and "/resend-activation" matcher paths
 * from the same "app.title" property, so they can't drift apart.
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
@RequestMapping("${app.title}/auth")
@Tag(name = "Email Verification API", description = "Account activation via emailed link (Stage 3/4 Step 10C)")
@RequiredArgsConstructor
public class EmailVerificationController {

    private final EmailVerificationService emailVerificationService;
    private final ClientApplicationService clientApplicationService;

    /** For a browser following the emailed link directly. */
    @GetMapping("/activate")
    public ResponseEntity<InternalAuthApiResponse<Void>> activateViaLink(@RequestParam String token) {
        ActivationResponse response = emailVerificationService.activate(token);
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage()));
    }

    /** For an API client (e.g. a SPA intercepting the link) submitting the token itself. */
    @PostMapping("/activate")
    public ResponseEntity<InternalAuthApiResponse<Void>> activateViaApi(@RequestBody ActivationRequest request) {
        ActivationResponse response = emailVerificationService.activate(request.getToken());
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage()));
    }

    @PostMapping("/resend-activation")
    public ResponseEntity<InternalAuthApiResponse<Void>> resendActivation(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody ResendActivationRequest request) {
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        ActivationResponse response = emailVerificationService.resendVerification(request.getEmail(), client.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage()));
    }
}

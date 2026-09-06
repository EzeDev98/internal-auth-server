package com.internal.auth.feature.identity.controller;

import com.internal.auth.common.security.AuthenticationHelper;
import com.internal.auth.feature.identity.dto.SetMfaRequest;
import com.internal.auth.feature.identity.service.MfaAdminService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Self-service counterpart to MfaAdminController (fixes "no self-service
 * MFA opt-in"). MfaAdminServiceImpl's setMfaEnabled was admin-only because,
 * at the time it was built, local login (Step 11A) issued no token yet for
 * a logged-in user to authenticate a follow-up call with - Step 12F has
 * since given local login a real self-issued bearer JWT
 * (LoginServiceImpl#mintAccessToken), so that blocker is gone.
 *
 * Deliberately takes no username or clientId - the caller can only ever
 * toggle their OWN MFA setting, with both resolved from their JWT:
 * username via AuthenticationHelper#getCurrentUsername (unchanged), and
 * client_application_id via AuthenticationHelper#getCurrentClientApplicationId
 * (a claim AuthorizationServerConfig#jwtTokenCustomizer now stamps onto
 * every self-issued access token - see LoginServiceImpl#mintAccessToken).
 * A missing claim (a Keycloak-issued admin JWT, or a client_credentials
 * token - neither carries it, and neither does a token minted before this
 * claim existed) is treated the same as a missing username: this endpoint
 * simply isn't usable with that token, and the caller needs to log in
 * again for a fresh one.
 *
 * No @PreAuthorize role check beyond "authenticated": gating this on a
 * specific role (e.g. basic_access) would leave it unusable for any
 * freshly-registered user, since registration assigns no default role yet
 * - a separate, still-open gap.
 *
 * Mapped under the same "${app.title}/mfa" base as MfaAdminController but
 * to the literal "/self" sub-path rather than "/{username}" - Spring's
 * request mapping always prefers a literal path segment over a variable
 * one for the same HTTP method, so "/api/v1/mfa/self" can never be
 * swallowed by MfaAdminController's "/api/v1/mfa/{username}" pattern.
 */
@RestController
@RequestMapping("${app.title}/mfa")
@Tag(name = "MFA Self-Service API", description = "Self-service toggle for a user's own login OTP step-up")
@RequiredArgsConstructor
public class MfaSelfServiceController {

    private final MfaAdminService mfaAdminService;
    private final AuthenticationHelper authenticationHelper;

    @PostMapping("/self")
    public ResponseEntity<Void> setMfaForSelf(@RequestBody SetMfaRequest request) {
        String username = authenticationHelper.getCurrentUsername();
        Long clientApplicationId = authenticationHelper.getCurrentClientApplicationId();
        if (username == null || clientApplicationId == null) {
            throw new AccessDeniedException("Unable to determine the authenticated user");
        }
        mfaAdminService.setMfaEnabled(username, clientApplicationId, request.isEnabled());
        return ResponseEntity.ok().build();
    }
}

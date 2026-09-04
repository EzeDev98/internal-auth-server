package com.internal.auth.feature.identity.controller;

import com.internal.auth.common.response.InternalAuthApiResponse;

import com.internal.auth.config.auth.Roles;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.dto.SetMfaRequest;
import com.internal.auth.feature.identity.service.MfaAdminService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Step 11E. Admin-only, authenticated the same way PermissionController/
 * ClientApplicationController are (${app.title} base path, no permitAll
 * rule needed - falls under .anyRequest().authenticated() plus
 * @PreAuthorize). For a user managing their own MFA setting, see
 * MfaSelfServiceController.
 *
 * Multi-tenant redesign: username alone is no longer enough to identify a
 * unique account (see User's class Javadoc, V8) - the admin must now also
 * supply clientId, resolved here to a client_application_id via
 * ClientApplicationService#getEnabledClientByClientId, the identical
 * pattern UserSessionController's admin session-invalidate endpoint
 * already uses.
 */
@RestController
@RequestMapping("${app.title}")
@Tag(name = "MFA Admin API", description = "Admin toggle for a user's login OTP step-up (Stage 3/4 Step 11E)")
@RequiredArgsConstructor
public class MfaAdminController {

    private final MfaAdminService mfaAdminService;
    private final ClientApplicationService clientApplicationService;

    @PutMapping("/users/{username}/mfa")
    @PreAuthorize(Roles.HAS_ADMIN)
    public ResponseEntity<InternalAuthApiResponse<Void>> setMfa(@PathVariable String username, @RequestParam String clientId, @RequestBody SetMfaRequest request) {
        ClientApplication client = clientApplicationService.getEnabledClientByClientId(clientId);
        mfaAdminService.setMfaEnabled(username, client.getId(), request.isEnabled());
        return ResponseEntity.ok(InternalAuthApiResponse.success("MFA setting updated successfully."));
    }
}

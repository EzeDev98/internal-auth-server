package com.internal.auth.feature.identity.controller;

import com.internal.auth.config.auth.Roles;
import com.internal.auth.feature.identity.dto.SetMfaRequest;
import com.internal.auth.feature.identity.service.MfaAdminService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Step 11E. Admin-only, authenticated the same way PermissionController/
 * ClientApplicationController are (${app.title} base path, no permitAll
 * rule needed - falls under .anyRequest().authenticated() plus
 * @PreAuthorize). See MfaAdminServiceImpl's Javadoc for why this isn't
 * self-service yet.
 */
@RestController
@RequestMapping("${app.title}/mfa")
@Tag(name = "MFA Admin API", description = "Admin toggle for a user's login OTP step-up (Stage 3/4 Step 11E)")
@RequiredArgsConstructor
public class MfaAdminController {

    private final MfaAdminService mfaAdminService;

    @PostMapping("/{username}")
    @PreAuthorize(Roles.HAS_ADMIN)
    public ResponseEntity<Void> setMfa(@PathVariable String username, @RequestBody SetMfaRequest request) {
        mfaAdminService.setMfaEnabled(username, request.isEnabled());
        return ResponseEntity.ok().build();
    }
}

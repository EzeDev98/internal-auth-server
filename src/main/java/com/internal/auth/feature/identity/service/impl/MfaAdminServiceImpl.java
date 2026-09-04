package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.common.exception.UserNotFoundException;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.identity.service.MfaAdminService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Step 11E. Shared by two controllers: MfaAdminController (admin, any
 * username within an admin-supplied clientId, @PreAuthorize(Roles.HAS_ADMIN))
 * and MfaSelfServiceController (any authenticated local user, own username
 * and own client_application_id, both resolved from their JWT -
 * self-service MFA opt-in previously didn't exist at all). The business
 * rules below and persistence are identical either way - only
 * caller-identity resolution and authorization differ, and that lives in
 * the two controllers, not here.
 *
 * Scoped by clientApplicationId (multi-tenant redesign - previously used
 * the unscoped UserRepository#findByUsername, the same class of gap
 * already fixed for SessionManagementServiceImpl#invalidateUserSessionByAdmin):
 * MfaAdminController resolves it from an admin-supplied clientId the same
 * way UserSessionController does; MfaSelfServiceController resolves it
 * from the caller's own JWT "client_application_id" claim (stamped by
 * AuthorizationServerConfig#jwtTokenCustomizer on every self-issued token
 * - see LoginServiceImpl#mintAccessToken).
 *
 * Enabling MFA now also requires the phone number on file to be verified,
 * not just present - added once self-service phone verification existed
 * to check against; previously a phone-only account's SMS step-up could
 * be turned on against a number nobody had confirmed was reachable.
 */
@Service
@RequiredArgsConstructor
public class MfaAdminServiceImpl implements MfaAdminService {

    private static final Logger log = LoggerFactory.getLogger(MfaAdminServiceImpl.class);

    private final UserRepository userRepository;

    @Override
    @Transactional
    public void setMfaEnabled(String username, Long clientApplicationId, boolean enabled) {
        User user = userRepository.findByUsernameAndClientApplicationId(username, clientApplicationId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (enabled) {
            if (user.getPhoneNumber() == null || user.getPhoneNumber().isBlank()) {
                throw new BadRequestException("Cannot enable MFA for a user with no phone number on file - the login step-up is SMS-based.");
            }
            if (!user.isPhoneVerified()) {
                throw new BadRequestException("Cannot enable MFA until the phone number on file has been verified.");
            }
        }

        user.setMfaEnabled(enabled);
        userRepository.save(user);
        log.info("MFA {} for user {}", enabled ? "enabled" : "disabled", username);
    }
}

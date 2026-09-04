package com.internal.auth.feature.identity.service;

/**
 * Shared by MfaAdminController (admin, clientApplicationId resolved from
 * an admin-supplied clientId) and MfaSelfServiceController (self-service,
 * clientApplicationId resolved from the caller's own JWT) - see
 * MfaAdminServiceImpl's Javadoc for the full reasoning.
 */
public interface MfaAdminService {
    void setMfaEnabled(String username, Long clientApplicationId, boolean enabled);
}

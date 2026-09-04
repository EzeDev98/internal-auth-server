package com.internal.auth.config.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/**
 * Small helper for pulling the caller's username (and, since the
 * self-service MFA endpoint needed it, their client_application_id) out
 * of the current request's JWT, and for the ownership/authority checks
 * that build on it. Centralized here so JwtSessionTrackingFilter and any
 * self-service endpoint share one claim-lookup convention instead of
 * re-deriving it inline.
 */
@Component
@RequiredArgsConstructor
public class AuthenticationHelper {

    /**
     * Returns the "preferred_username" claim of the current request's JWT
     * (the conventional OIDC/Keycloak username claim), falling back to the
     * token subject if it's absent. Returns null if there is no
     * JWT-authenticated principal on the current request.
     */
    public String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication != null && authentication.getPrincipal() instanceof Jwt jwt)) {
            return null;
        }

        String username = jwt.getClaimAsString("preferred_username");
        return username != null ? username : jwt.getSubject();
    }

    /**
     * Returns the "client_application_id" claim of the current request's
     * JWT - stamped by AuthorizationServerConfig#jwtTokenCustomizer onto
     * every self-issued access token minted for a local user
     * (LoginServiceImpl#mintAccessToken sets it via the principal's
     * details). Returns null if there is no JWT-authenticated principal,
     * or the claim is absent - a Keycloak-issued admin JWT and a
     * client_credentials token both lack it, since neither represents one
     * specific local user in one specific client application.
     */
    public Long getCurrentClientApplicationId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication != null && authentication.getPrincipal() instanceof Jwt jwt)) {
            return null;
        }

        Object claim = jwt.getClaim("client_application_id");
        return (claim instanceof Number number) ? number.longValue() : null;
    }

    /**
     * True if the current request's authorities include the admin role
     * ({@link Roles#HAS_ADMIN}'s underlying authority name). Matches
     * WebSecurityConfig's {@code GrantedAuthorityDefaults("")} — authorities
     * are compared as literal, unprefixed strings, same as every
     * {@code hasRole(...)} check elsewhere in this app.
     */
    public boolean isAdmin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return false;
        }
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch("create-admin"::equalsIgnoreCase);
    }

    /**
     * Fixes the confirmed IDOR on {@code GET /groups/users/{username}}
     * (Stage 1 assessment, "Immediate Next Steps" #3): that endpoint's
     * {@code @PreAuthorize(Roles.HAS_ADMIN_OR_USER)} only checked that the
     * caller was *some* authenticated user, not that they owned the
     * requested {@code username} — so any logged-in user could read any
     * other user's group memberships just by changing the path variable.
     *
     * <p>Keys off {@code username} rather than the old wmUniqueId (removed
     * in the Stage 2 item 1 follow-up) — since the caller's own username is
     * already available from their JWT, this is now a plain string compare
     * with no database lookup needed.
     *
     * <p>Throws {@link AccessDeniedException} (routed to the already-wired
     * {@code CustomAccessDenied} handler — see WebSecurityConfig) unless the
     * caller is an admin or the requested {@code username} is their own.
     */
    public void requireSelfOrAdmin(String username) {
        if (isAdmin()) {
            return;
        }

        String currentUsername = getCurrentUsername();
        if (currentUsername == null) {
            throw new AccessDeniedException("Unable to determine the authenticated user");
        }

        if (!currentUsername.equals(username)) {
            throw new AccessDeniedException("You may only access your own resource");
        }
    }
}

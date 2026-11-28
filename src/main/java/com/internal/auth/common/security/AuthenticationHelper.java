package com.internal.auth.common.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/** Reads the caller's identity from the current JWT and performs ownership checks. */
@Component
@RequiredArgsConstructor
public class AuthenticationHelper {
    public String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication != null && authentication.getPrincipal() instanceof Jwt jwt)) {
            return null;
        }

        String username = jwt.getClaimAsString("preferred_username");
        return username != null ? username : jwt.getSubject();
    }

    public String getCurrentServiceClientId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication != null && authentication.getPrincipal() instanceof Jwt jwt)) {
            return null;
        }
        return jwt.getSubject();
    }

    public Long getCurrentClientApplicationId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication != null && authentication.getPrincipal() instanceof Jwt jwt)) {
            return null;
        }

        Object claim = jwt.getClaim("client_application_id");
        return (claim instanceof Number number) ? number.longValue() : null;
    }

    public boolean isAdmin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return false;
        }
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch("create-admin"::equalsIgnoreCase);
    }

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

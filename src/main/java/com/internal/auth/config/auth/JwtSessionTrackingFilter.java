package com.internal.auth.config.auth;

import com.internal.auth.config.redis.SessionStorage;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.session.service.SessionManagementService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Backfills a local {@code UserSession} row the first time an authenticated
 * request is seen for a given bearer token — because frontends authenticate
 * against the configured OIDC issuer's own hosted login page (Authorization
 * Code flow) rather than a local "/login" endpoint here, the backend never
 * receives a discrete "login" event, only ordinary bearer-token-bearing API
 * calls. {@code SessionManagementService.hasActiveSession}/
 * {@code invalidateSession} both depend on a {@code UserSession} row
 * existing, so this filter is what keeps that table populated.
 *
 * <p>Deliberately cheap: a short-lived Redis flag prevents this from hitting
 * the database on every single request once a session has already been
 * recorded recently, and any failure here is logged and swallowed rather
 * than allowed to break the actual request.
 *
 * <p>NOTE: this only creates/refreshes the session row. It does not stamp
 * a separate per-user "last active" timestamp — that capability doesn't
 * exist on {@link SessionManagementService} today (the earlier version of
 * this filter assumed a wider {@code SessionService} interface that was
 * never actually built). Revisit if activity tracking beyond "has an
 * active session" is needed.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtSessionTrackingFilter extends OncePerRequestFilter {

    private static final String TRACKED_CACHE = "JWT_SESSION_TRACKED";
    private static final long TRACKED_CACHE_TTL_SECONDS = 300L;

    private final SessionManagementService sessionManagementService;
    private final SessionStorage sessionStorage;
    private final AuthenticationHelper authenticationHelper;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            trackSessionIfNeeded(request);
        } catch (Exception ex) {
            // Session bookkeeping should never take down a real request.
            log.warn("Failed to track session from JWT: {}", ex.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private void trackSessionIfNeeded(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication != null && authentication.getPrincipal() instanceof Jwt jwt)) {
            return;
        }

        String username = authenticationHelper.getCurrentUsername();
        if (username == null) {
            return;
        }

        String sid = extractSessionId(jwt);
        String cacheKey = sid != null ? sid : username;

        if (sessionStorage.getCache(TRACKED_CACHE, cacheKey) != null) {
            return; // already tracked recently — skip the database round trip
        }

        String rawToken = extractRawToken(request);
        if (rawToken == null) {
            return;
        }

        Optional<User> user = resolveUser(username);
        if (user.isEmpty()) {
            log.debug("No local User record for '{}' — skipping session tracking for this request", username);
            return;
        }

        sessionManagementService.createSession(user.get().getId(), user.get().getPhoneNumber(), rawToken);
        sessionStorage.putCache(TRACKED_CACHE, cacheKey, Boolean.TRUE, TRACKED_CACHE_TTL_SECONDS);
    }

    /**
     * Step 3 (session-tracking lookup fix): scoped by client_application_id
     * when the current token carries that claim (a self-issued local-login
     * token - see AuthenticationHelper#getCurrentClientApplicationId and
     * LoginServiceImpl#mintAccessToken). A Keycloak-issued token carries no
     * such claim and predates the tenant concept entirely, so it can't be
     * scoped that way - instead this falls back to findAllByUsername and
     * refuses to guess when the username collides across more than one
     * tenant, rather than risking Spring Data's opaque
     * IncorrectResultSizeDataAccessException or an arbitrary match.
     */
    private Optional<User> resolveUser(String username) {
        Long clientApplicationId = authenticationHelper.getCurrentClientApplicationId();
        if (clientApplicationId != null) {
            return userRepository.findByUsernameAndClientApplicationId(username, clientApplicationId);
        }

        List<User> matches = userRepository.findAllByUsername(username);
        if (matches.size() > 1) {
            log.warn("Skipping session tracking for '{}': username exists in more than one "
                    + "client application and this token carries no client_application_id claim "
                    + "to disambiguate.", username);
            return Optional.empty();
        }
        return matches.stream().findFirst();
    }

    private String extractRawToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return null;
        }
        return header.substring(7).trim();
    }

    /**
     * Shared with {@code UserSessionController}'s self-service session-status
     * check, so the "sid, falling back to session_state" claim lookup only
     * lives in one place.
     */
    public static String extractSessionId(Jwt jwt) {
        String sid = jwt.getClaimAsString("sid");
        if (sid == null) {
            // Some issuers expose the session id under this claim name instead.
            sid = jwt.getClaimAsString("session_state");
        }
        return sid;
    }
}

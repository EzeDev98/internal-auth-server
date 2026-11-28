package com.internal.auth.config.auth;

import com.internal.auth.common.crypto.TokenHasher;
import com.internal.auth.config.redis.SessionStorage;
import com.internal.auth.common.security.AuthenticationHelper;
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

/** Records a local user session the first time a bearer token is seen. */
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
    private final TokenHasher tokenHasher;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            trackSessionIfNeeded(request);
        } catch (Exception ex) {
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
        String rawToken = extractRawToken(request);
        if (rawToken == null) {
            return;
        }
        String cacheKey = resolveCacheKey(sid, username, rawToken);

        if (sessionStorage.getCache(TRACKED_CACHE, cacheKey) != null) {
            return;
        }

        Optional<User> user = resolveUser(username);
        if (user.isEmpty()) {
            log.debug("No local User record for '{}' — skipping session tracking for this request", username);
            return;
        }

        sessionManagementService.createSession(user.get().getId(), user.get().getPhoneNumber(), rawToken, request.getRemoteAddr(), request.getHeader("User-Agent"));
        sessionStorage.putCache(TRACKED_CACHE, cacheKey, Boolean.TRUE, TRACKED_CACHE_TTL_SECONDS);
    }

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

    private String resolveCacheKey(String sid, String username, String rawToken) {
        if (sid != null) {
            return sid;
        }
        Long clientApplicationId = authenticationHelper.getCurrentClientApplicationId();
        String base = clientApplicationId != null ? clientApplicationId + ":" + username : username;
        return base + ":" + tokenHasher.sha256Hex(rawToken);
    }

    private String extractRawToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return null;
        }
        return header.substring(7).trim();
    }

    public static String extractSessionId(Jwt jwt) {
        String sid = jwt.getClaimAsString("sid");
        if (sid == null) {
            sid = jwt.getClaimAsString("session_state");
        }
        return sid;
    }
}

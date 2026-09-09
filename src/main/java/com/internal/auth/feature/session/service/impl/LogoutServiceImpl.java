package com.internal.auth.feature.session.service.impl;

import com.internal.auth.common.crypto.TokenHasher;
import com.internal.auth.feature.session.dto.LogoutResponse;
import com.internal.auth.feature.session.model.UserSession;
import com.internal.auth.feature.session.repository.UserSessionRepository;
import com.internal.auth.feature.session.service.LogoutService;
import com.internal.auth.feature.session.service.SessionManagementService;
import com.internal.auth.common.exception.BadRequestException;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

@Service
public class LogoutServiceImpl implements LogoutService {

    private static final Logger log = LoggerFactory.getLogger(LogoutServiceImpl.class);
    private final UserSessionRepository userSessionRepo;
    private final SessionManagementService sessionManagementService;
    private final TokenHasher tokenHasher;
    private final OAuth2AuthorizationService authorizationService;

    public LogoutServiceImpl(UserSessionRepository userSessionRepo, SessionManagementService sessionManagementService,
                             TokenHasher tokenHasher, OAuth2AuthorizationService authorizationService) {
        this.userSessionRepo = userSessionRepo;
        this.sessionManagementService = sessionManagementService;
        this.tokenHasher = tokenHasher;
        this.authorizationService = authorizationService;
    }

    @Transactional
    @Override
    public LogoutResponse logout(String token) {

        if (token == null || token.trim().isEmpty()) {
            log.warn("Attempted logout with null or empty token");
            throw new BadRequestException("Invalid token");
        }

        try {

            // Step 15D: revoke the OAuth2Authorization record this access
            // token belongs to - and with it, whatever refresh token
            // mintTokens() minted alongside it on the same row - BEFORE
            // the UserSession check below, and regardless of whether that
            // check finds anything. Without this, "logout" only ever
            // deleted the bookkeeping UserSession row; the actual
            // credential this session was built on - specifically its
            // refresh token - stayed fully valid until its own TTL
            // expired, so a client (or anyone holding a copy of that
            // refresh token) could mint a brand new access token
            // immediately after "logging out", making logout not actually
            // end the session. Best-effort and null-safe: a Keycloak-
            // issued legacy token was never persisted in this table to
            // begin with, so findByToken correctly returns null for one
            // and logout proceeds via the UserSession path exactly as it
            // did before this change.
            OAuth2Authorization authorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
            if (authorization != null) {
                authorizationService.remove(authorization);
                log.info("Revoked self-issued authorization (access + refresh token) for user: {}", authorization.getPrincipalName());
            }

            UserSession session = userSessionRepo.findByTokenHash(tokenHasher.sha256Hex(token))
                    .orElseThrow(() -> new BadRequestException("No active session found"));

            sessionManagementService.invalidateSession(token);
            log.info("Session deleted for user: {}", session.getPhoneNumber());

            return new LogoutResponse("Logout successful", HttpServletResponse.SC_OK);
        } catch (BadRequestException ex) {
            log.warn("Logout failed: {}", ex.getMessage());
            return new LogoutResponse(ex.getMessage(), HttpServletResponse.SC_BAD_REQUEST);
        } catch (Exception ex) {
            log.error("Error during logout: {}", ex.getMessage());
            return new LogoutResponse("Logout failed. Please try again.", HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
}
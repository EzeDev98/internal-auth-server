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
import org.springframework.stereotype.Service;

@Service
public class LogoutServiceImpl implements LogoutService {

    private static final Logger log = LoggerFactory.getLogger(LogoutServiceImpl.class);
    private final UserSessionRepository userSessionRepo;
    private final SessionManagementService sessionManagementService;
    private final TokenHasher tokenHasher;

    public LogoutServiceImpl(UserSessionRepository userSessionRepo, SessionManagementService sessionManagementService, TokenHasher tokenHasher) {
        this.userSessionRepo = userSessionRepo;
        this.sessionManagementService = sessionManagementService;
        this.tokenHasher = tokenHasher;
    }

    @Transactional
    @Override
    public LogoutResponse logout(String token) {

        if (token == null || token.trim().isEmpty()) {
            log.warn("Attempted logout with null or empty token");
            throw new BadRequestException("Invalid token");
        }

        try {

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

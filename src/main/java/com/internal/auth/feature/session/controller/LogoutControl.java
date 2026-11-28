package com.internal.auth.feature.session.controller;

import com.internal.auth.common.response.InternalAuthApiResponse;

import com.internal.auth.feature.session.dto.LogoutResponse;
import com.internal.auth.feature.session.dto.OwnSessionResponse;
import com.internal.auth.feature.session.dto.SignedOutSessionsResponse;
import com.internal.auth.feature.session.service.LogoutService;
import com.internal.auth.feature.session.service.SessionManagementService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Endpoints for logging out and ending sessions. */
@AllArgsConstructor
@RestController
@RequestMapping("${app.title}")
@Tag(name = "Logout API", description = "Resource for terminating a user's authenticated session")
public class LogoutControl {

    private static final String BEARER_PREFIX = "Bearer ";

    private final LogoutService logoutService;
    private final SessionManagementService sessionManagementService;

    @DeleteMapping("/session")
    public ResponseEntity<InternalAuthApiResponse<LogoutResponse>> logout(@RequestHeader("Authorization") String authHeader) {
        LogoutResponse response = logoutService.logout(tokenFrom(authHeader));
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    @DeleteMapping("/session/all")
    public ResponseEntity<InternalAuthApiResponse<LogoutResponse>> logoutAll(@RequestHeader("Authorization") String authHeader) {
        LogoutResponse response = logoutService.logoutAll(tokenFrom(authHeader));
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    @GetMapping("/session")
    public ResponseEntity<InternalAuthApiResponse<java.util.List<OwnSessionResponse>>> listOwnSessions(@RequestHeader("Authorization") String authHeader) {
        return ResponseEntity.ok(InternalAuthApiResponse.success(sessionManagementService.listOwnSessions(tokenFrom(authHeader))));
    }

    @DeleteMapping("/session/others")
    public ResponseEntity<InternalAuthApiResponse<SignedOutSessionsResponse>> logoutOthers(@RequestHeader("Authorization") String authHeader) {
        int signedOut = sessionManagementService.revokeOtherSessions(tokenFrom(authHeader));
        return ResponseEntity.ok(InternalAuthApiResponse.success("Signed out of other devices", new SignedOutSessionsResponse(signedOut)));
    }

    @DeleteMapping("/session/{sessionId}")
    public ResponseEntity<InternalAuthApiResponse<Void>> revokeOwnSession(@RequestHeader("Authorization") String authHeader,
                                                                         @PathVariable Long sessionId) {
        sessionManagementService.revokeOwnSession(tokenFrom(authHeader), sessionId);
        return ResponseEntity.ok(InternalAuthApiResponse.success("Session signed out"));
    }

    private static String tokenFrom(String authHeader) {
        return authHeader.replace(BEARER_PREFIX, "").trim();
    }
}

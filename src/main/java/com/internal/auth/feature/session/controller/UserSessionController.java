package com.internal.auth.feature.session.controller;

import com.internal.auth.common.response.InternalAuthApiResponse;
import com.internal.auth.common.exception.BadRequestException;

import com.internal.auth.config.auth.Roles;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.session.client.SyncPointSessionClient;
import com.internal.auth.feature.session.client.AhorraSessionClient;
import com.internal.auth.feature.session.dto.InvalidatedSessionResponse;
import com.internal.auth.feature.session.dto.PagedAdminSessionsResponse;
import com.internal.auth.feature.session.service.SessionManagementService;
import com.internal.auth.common.constant.AppConstant;
import com.internal.auth.common.util.RateLimiterService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Duration;

/** Endpoints for viewing and invalidating user sessions. */
@RequiredArgsConstructor
@RestController
@RequestMapping("${app.title}")
@Tag(name = "User Session Api", description = "Resource for managing users sessions")
public class UserSessionController {

    private final SessionManagementService sessionService;
    private final ClientApplicationService clientApplicationService;
    private final RateLimiterService rateLimiterService;
    private final SyncPointSessionClient syncPointSessionClient;
    private final AhorraSessionClient ahorraSessionClient;

    @Value("${sync-point.internal-auth-client-id:sync-point}")
    private String syncPointClientId;

    @Value("${ahorra.internal-auth-client-id:ahorra}")
    private String ahorraClientId;

    @Operation(method = "POST", summary = "Invalidate session", description = "This an admin endpoint for invalidating a user's session in case they mistakenly got locked out of the app. This will be on very rare occasion")
    @PreAuthorize(Roles.HAS_ADMIN)
    @DeleteMapping("/users/{username}/sessions")
    public ResponseEntity<InternalAuthApiResponse<InvalidatedSessionResponse>> invalidateSession(@PathVariable String username, @RequestParam String clientId, HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(AppConstant.SESSION_INVALIDATE_RATE_LIMIT_KEY_PREFIX + httpRequest.getRemoteAddr(), AppConstant.MAX_SESSION_INVALIDATE_REQUEST, Duration.ofHours(AppConstant.SESSION_INVALIDATE_RATE_LIMIT_DURATION_HOURS));
        ClientApplication client = clientApplicationService.getEnabledClientByClientId(clientId);
        InvalidatedSessionResponse response = sessionService.invalidateUserSessionByAdmin(username, client.getId());
        if (syncPointClientId.equals(clientId)) {
            syncPointSessionClient.notifySessionInvalidated(username);
        }
        if (ahorraClientId.equals(clientId)) {
            ahorraSessionClient.notifySessionInvalidated(username);
        }
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    @Operation(method = "GET", summary = "List sessions", description = "Paginated, filterable session directory. username (with clientId) filters by user; ipAddress and device match as a substring.")
    @PreAuthorize(Roles.HAS_ADMIN)
    @GetMapping("/admin/sessions")
    public ResponseEntity<InternalAuthApiResponse<PagedAdminSessionsResponse>> listSessions(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String clientId,
            @RequestParam(required = false) String ipAddress,
            @RequestParam(required = false) String device,
            @RequestParam(required = false) Boolean active,
            @PageableDefault(size = 20, sort = "id", direction = Sort.Direction.DESC) Pageable pageable) {
        if (username != null && clientId == null) {
            throw new BadRequestException("clientId is required when filtering by username");
        }
        Long clientApplicationId = clientId == null ? null : clientApplicationService.getEnabledClientByClientId(clientId).getId();
        PagedAdminSessionsResponse response = sessionService.listSessions(username, clientApplicationId, ipAddress, device, active, pageable);
        return ResponseEntity.ok(InternalAuthApiResponse.success(response));
    }

}

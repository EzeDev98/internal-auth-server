package com.internal.auth.feature.session.controller;

import com.internal.auth.common.response.InternalAuthApiResponse;
import com.internal.auth.common.exception.BadRequestException;

import com.internal.auth.config.auth.Roles;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.session.client.SyncPointSessionClient;
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

/**
 * Step 11B: @RequestParam changed from phoneNumber to username. Keeping it
 * phoneNumber-based would have left this endpoint permanently unable to
 * invalidate a session for any email-only user (nothing to search by) -
 * username is mandatory on every account, consistent with how the rest of
 * this app moved off phone/wmUniqueId-based lookups onto username
 * (Stage 2 item 1).
 *
 * Multi-tenant redesign, sessions step: username alone is no longer
 * enough to identify a unique account (see User's class Javadoc, V8) - the
 * admin must now also supply clientId, resolved here to a
 * client_application_id via ClientApplicationService#getEnabledClientByClientId
 * (a plain lookup, not a credential check - this caller is already an
 * authenticated admin, not an integrating app authenticating itself).
 */
@RequiredArgsConstructor
@RestController
@RequestMapping("${app.title}")
@Tag(name = "User Session Api", description = "Resource for managing users sessions")
public class UserSessionController {

    private final SessionManagementService sessionService;
    private final ClientApplicationService clientApplicationService;
    private final RateLimiterService rateLimiterService;
    private final SyncPointSessionClient syncPointSessionClient;

    /**
     * clientId SyncPoint is registered under in THIS app's client_applications
     * table (see application.properties). Only this client gets the push
     * below - SyncPoint is the one integrating app with its own downstream
     * per-user session row that needs to hear about this action directly;
     * every other client is unaffected.
     */
    @Value("${sync-point.internal-auth-client-id:sync-point}")
    private String syncPointClientId;

    /**
     * Fixes a confirmed broken-access-control gap found while confirming
     * Stage 1 punch-list item 5 (session tracking): this endpoint's own
     * Javadoc always described it as admin-only, but nothing enforced that
     * — WebSecurityConfig only required an authenticated caller, so any
     * logged-in user (any role) could force-logout an arbitrary other user.
     * Gated the same way the item-3 fixes gated PermissionController: an
     * explicit @PreAuthorize check.
     */
    @Operation(method = "POST", summary = "Invalidate session", description = "This an admin endpoint for invalidating a user's session in case they mistakenly got locked out of the app. This will be on very rare occasion")
    @PreAuthorize(Roles.HAS_ADMIN)
    @DeleteMapping("/users/{username}/sessions")
    public ResponseEntity<InternalAuthApiResponse<InvalidatedSessionResponse>> invalidateSession(@PathVariable String username, @RequestParam String clientId, HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(AppConstant.SESSION_INVALIDATE_RATE_LIMIT_KEY_PREFIX + httpRequest.getRemoteAddr(), AppConstant.MAX_SESSION_INVALIDATE_REQUEST, Duration.ofHours(AppConstant.SESSION_INVALIDATE_RATE_LIMIT_DURATION_HOURS));
        ClientApplication client = clientApplicationService.getEnabledClientByClientId(clientId);
        InvalidatedSessionResponse response = sessionService.invalidateUserSessionByAdmin(username, client.getId());
        // Push straight to SyncPoint so its own user_sessions row is freed now, not just on
        // the user's next login attempt (see SyncPointSessionClient's Javadoc). Fired even if
        // this app had no active UserSession row to close above (response 404) - the
        // oauth2_authorization rows behind it are deleted unconditionally by
        // invalidateUserSessionByAdmin, so SyncPoint's own record is stale either way.
        if (syncPointClientId.equals(clientId)) {
            syncPointSessionClient.notifySessionInvalidated(username);
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

package com.internal.auth.feature.session.web;

import com.internal.auth.config.auth.Roles;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.session.dto.InvalidatedSessionResponse;
import com.internal.auth.feature.session.service.SessionManagementService;
import com.internal.auth.common.constant.AppConstant;
import com.internal.auth.common.util.RateLimiterService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
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
    @PostMapping("/session/invalidate")
    public ResponseEntity<InvalidatedSessionResponse> invalidateSession(@RequestParam String username, @RequestParam String clientId, HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(AppConstant.SESSION_INVALIDATE_RATE_LIMIT_KEY_PREFIX + httpRequest.getRemoteAddr(), AppConstant.MAX_SESSION_INVALIDATE_REQUEST, Duration.ofHours(AppConstant.SESSION_INVALIDATE_RATE_LIMIT_DURATION_HOURS));
        ClientApplication client = clientApplicationService.getEnabledClientByClientId(clientId);
        InvalidatedSessionResponse response = sessionService.invalidateUserSessionByAdmin(username, client.getId());
        return ResponseEntity.ok(response);
    }
}

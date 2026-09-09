package com.internal.auth.feature.identity.controller;

import com.internal.auth.common.response.InternalAuthApiResponse;
import com.internal.auth.common.security.AuthenticationHelper;
import com.internal.auth.config.auth.Roles;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.dto.request.AdminCreateUserRequest;
import com.internal.auth.feature.identity.dto.request.AdminUpdateUserRequest;
import com.internal.auth.feature.identity.dto.response.PagedUsersResponse;
import com.internal.auth.feature.identity.dto.response.UserProfileResponse;
import com.internal.auth.feature.identity.service.AdminUserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * Step 2A (React Admin Client plan v4). Admin-only user directory:
 * list/search, single-profile lookup, and enable/disable + verified-flag
 * edits. Mapped under the same "${app.title}/users/{username}" resource
 * path MfaAdminController and UserSessionController already use for other
 * admin actions on a user, rather than a separate "/admin/users" prefix -
 * keeps every admin action on the users resource under one path family.
 *
 * clientId is required on the single-user endpoints for the same reason
 * MfaAdminController/UserSessionController require it: username is only
 * unique per client_application_id since the multi-tenant redesign (see
 * User's class Javadoc, V8), so username alone can't safely resolve one
 * row. It's optional on the list endpoint - omit it to see users across
 * every client application, or supply it to scope the list to one tenant.
 *
 * No rate limiting here, matching precedent: MfaAdminController's PUT
 * /users/{username}/mfa has none either - that hardening (Step 14C/14D)
 * was applied only to a specific set of higher-impact actions (session
 * invalidation, secret/key rotation), not to every admin-gated endpoint.
 */
@RestController
@RequestMapping("${app.title}")
@Tag(name = "Admin User API", description = "Admin user directory: list/search, profile lookup, enable/disable and verified-flag edits")
@RequiredArgsConstructor
public class AdminUserController {

    private final AdminUserService adminUserService;
    private final ClientApplicationService clientApplicationService;
    private final AuthenticationHelper authenticationHelper;

    @Operation(method = "GET", summary = "List users", description = "Paginated, filterable user directory. search matches username, phone, or email.")
    @PreAuthorize(Roles.HAS_ADMIN)
    @GetMapping("/users")
    public ResponseEntity<InternalAuthApiResponse<PagedUsersResponse>> listUsers(
            @RequestParam(required = false) String clientId,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) Boolean enabled,
            @PageableDefault(size = 20, sort = "id") Pageable pageable) {
        Long clientApplicationId = clientId == null ? null : clientApplicationService.getEnabledClientByClientId(clientId).getId();
        PagedUsersResponse response = adminUserService.listUsers(clientApplicationId, search, enabled, pageable);
        return ResponseEntity.ok(InternalAuthApiResponse.success(response));
    }

    @Operation(method = "GET", summary = "Get user profile", description = "Single user's profile: contact info, verification flags, enabled state, MFA status, created date.")
    @PreAuthorize(Roles.HAS_ADMIN)
    @GetMapping("/users/{username}")
    public ResponseEntity<InternalAuthApiResponse<UserProfileResponse>> getUser(@PathVariable String username, @RequestParam String clientId) {
        ClientApplication client = clientApplicationService.getEnabledClientByClientId(clientId);
        UserProfileResponse response = adminUserService.getUserProfile(username, client.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success(response));
    }

    @Operation(method = "PATCH", summary = "Update user", description = "Admin edits: enable/disable the account, or correct email/phone verified flags. Any field left null is left unchanged.")
    @PreAuthorize(Roles.HAS_ADMIN)
    @PatchMapping("/users/{username}")
    public ResponseEntity<InternalAuthApiResponse<UserProfileResponse>> updateUser(@PathVariable String username, @RequestParam String clientId, @RequestBody AdminUpdateUserRequest request) {
        ClientApplication client = clientApplicationService.getEnabledClientByClientId(clientId);
        UserProfileResponse response = adminUserService.updateUser(username, client.getId(), request);
        return ResponseEntity.ok(InternalAuthApiResponse.success("User updated successfully.", response));
    }

    @Operation(method = "POST", summary = "Create user", description = "Admin-created account: password is admin-supplied, contact info is marked verified immediately, and no role/permission-group is assigned - use the existing role/group endpoints separately.")
    @PreAuthorize(Roles.HAS_ADMIN)
    @PostMapping("/users")
    public ResponseEntity<InternalAuthApiResponse<UserProfileResponse>> createUser(@RequestParam String clientId, @RequestBody AdminCreateUserRequest request) {
        ClientApplication client = clientApplicationService.getEnabledClientByClientId(clientId);
        UserProfileResponse response = adminUserService.createUser(client.getId(), request);
        return ResponseEntity.status(HttpStatus.CREATED).body(InternalAuthApiResponse.success("User created successfully.", response));
    }

    @Operation(summary = "Delete user", description = "Deletes a locally registered user (and their role/permission-group assignments), scoped to the calling client application. Used by integrating apps to roll back a failed registration.")
    @DeleteMapping("/users")
    public ResponseEntity<InternalAuthApiResponse<Void>> deleteUser(@RequestParam String internalAuthUserId) {
        String callerClientId = authenticationHelper.getCurrentServiceClientId();
        ClientApplication client = clientApplicationService.getEnabledClientByClientId(callerClientId);
        adminUserService.deleteUser(internalAuthUserId, client.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success("User deleted", null));
    }
}

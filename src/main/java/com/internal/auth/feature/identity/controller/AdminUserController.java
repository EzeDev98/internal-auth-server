package com.internal.auth.feature.identity.controller;

import com.internal.auth.common.response.InternalAuthApiResponse;
import com.internal.auth.common.security.AuthenticationHelper;
import com.internal.auth.config.auth.Roles;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.dto.request.AdminCreateUserRequest;
import com.internal.auth.feature.identity.dto.request.AdminResetPasswordRequest;
import com.internal.auth.feature.identity.dto.request.AdminUpdateUserRequest;
import com.internal.auth.feature.identity.dto.response.PagedUsersResponse;
import com.internal.auth.feature.identity.dto.response.UserCredentialResponse;
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

/** Admin endpoints for listing, viewing and managing users. */
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

    @Operation(method = "GET", summary = "Get user profile", description = "Single user's profile: contact info, verification flags, enabled state, created date.")
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

    @Operation(method = "GET", summary = "Get credential", description = "The account's password credential: type and when it was created/last changed. This app stores one credential per user.")
    @PreAuthorize(Roles.HAS_ADMIN)
    @GetMapping("/users/{username}/credentials")
    public ResponseEntity<InternalAuthApiResponse<UserCredentialResponse>> getCredential(@PathVariable String username, @RequestParam String clientId) {
        ClientApplication client = clientApplicationService.getEnabledClientByClientId(clientId);
        UserCredentialResponse response = adminUserService.getCredential(username, client.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success(response));
    }

    @Operation(method = "POST", summary = "Reset password", description = "Admin sets a new password directly for the account and invalidates its active session.")
    @PreAuthorize(Roles.HAS_ADMIN)
    @PostMapping("/users/{username}/credentials/reset")
    public ResponseEntity<InternalAuthApiResponse<Void>> resetPassword(@PathVariable String username, @RequestParam String clientId, @RequestBody AdminResetPasswordRequest request) {
        ClientApplication client = clientApplicationService.getEnabledClientByClientId(clientId);
        adminUserService.resetPassword(username, client.getId(), request);
        return ResponseEntity.ok(InternalAuthApiResponse.success("Password reset successfully."));
    }
}

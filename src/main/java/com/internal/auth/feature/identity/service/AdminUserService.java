package com.internal.auth.feature.identity.service;

import com.internal.auth.feature.identity.dto.request.AdminCreateUserRequest;
import com.internal.auth.feature.identity.dto.request.AdminResetPasswordRequest;
import com.internal.auth.feature.identity.dto.request.AdminUpdateUserRequest;
import com.internal.auth.feature.identity.dto.response.PagedUsersResponse;
import com.internal.auth.feature.identity.dto.response.UserCredentialResponse;
import com.internal.auth.feature.identity.dto.response.UserProfileResponse;
import org.springframework.data.domain.Pageable;

/**
 * Step 2A (React Admin Client plan v4): admin user directory backing the
 * Users - List and Users - Detail screens. See AdminUserController's
 * Javadoc for why clientApplicationId is optional for listUsers but
 * mandatory for the single-user methods.
 */
public interface AdminUserService {

    PagedUsersResponse listUsers(Long clientApplicationId, String search, Boolean enabled, Pageable pageable);

    UserProfileResponse getUserProfile(String username, Long clientApplicationId);

    /**
     * Applies only the non-null fields on request; throws
     * UserNotFoundException if no user matches username within
     * clientApplicationId.
     */
    UserProfileResponse updateUser(String username, Long clientApplicationId, AdminUpdateUserRequest request);

    /**
     * Step 2G. Admin-created account: password is admin-supplied (not
     * auto-generated), and contact info is marked verified immediately -
     * an admin is vouching for this account, same rationale
     * AdminRegistrationServiceImpl's bootstrap flow already uses. No role
     * or permission-group is assigned here; that's left as a deliberate
     * separate step via the existing role/group assignment endpoints.
     */
    UserProfileResponse createUser(Long clientApplicationId, AdminCreateUserRequest request);

    void deleteUser(String internalAuthUserId, Long clientApplicationId);

    /**
     * Step 2H (Users - Detail Credentials tab). Always resolves - every
     * account has a password (User.password is set at creation, either by
     * self-registration or #createUser above).
     */
    UserCredentialResponse getCredential(String username, Long clientApplicationId);

    /**
     * Step 2H. Admin sets a new password directly for the account - no
     * OTP/token round trip, unlike PasswordResetServiceImpl's self-service
     * flow. Also invalidates the user's active session (same
     * SessionManagementService#invalidateActiveSessionForUser call
     * PasswordResetServiceImpl#completeReset makes), forcing a fresh login
     * with the new password.
     */
    void resetPassword(String username, Long clientApplicationId, AdminResetPasswordRequest request);
}

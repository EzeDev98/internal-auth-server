package com.internal.auth.feature.identity.service;

import com.internal.auth.feature.identity.dto.AdminCreateUserRequest;
import com.internal.auth.feature.identity.dto.AdminUpdateUserRequest;
import com.internal.auth.feature.identity.dto.PagedUsersResponse;
import com.internal.auth.feature.identity.dto.UserProfileResponse;
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
}

package com.internal.auth.feature.identity.service;

import com.internal.auth.feature.identity.dto.request.AdminCreateUserRequest;
import com.internal.auth.feature.identity.dto.request.AdminResetPasswordRequest;
import com.internal.auth.feature.identity.dto.request.AdminUpdateUserRequest;
import com.internal.auth.feature.identity.dto.response.PagedUsersResponse;
import com.internal.auth.feature.identity.dto.response.UserCredentialResponse;
import com.internal.auth.feature.identity.dto.response.UserProfileResponse;
import org.springframework.data.domain.Pageable;

/** Admin operations for listing, viewing and managing users. */
public interface AdminUserService {

    PagedUsersResponse listUsers(Long clientApplicationId, String search, Boolean enabled, Pageable pageable);

    UserProfileResponse getUserProfile(String username, Long clientApplicationId);

    UserProfileResponse updateUser(String username, Long clientApplicationId, AdminUpdateUserRequest request);

    UserProfileResponse createUser(Long clientApplicationId, AdminCreateUserRequest request);

    void deleteUser(String internalAuthUserId, Long clientApplicationId);

    UserCredentialResponse getCredential(String username, Long clientApplicationId);

    void resetPassword(String username, Long clientApplicationId, AdminResetPasswordRequest request);
}

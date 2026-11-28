package com.internal.auth.feature.rbac.service;

import com.internal.auth.common.response.BaseResponse;

/** Operations for placing users in default permission groups. */
public interface UserService {
    BaseResponse addUserToDefaultPermissionGroup(String username);
    BaseResponse addUserToAdminPermissionGroup(String username);
}

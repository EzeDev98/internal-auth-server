package com.internal.auth.feature.passwordreset.service;

import com.internal.auth.feature.identity.dto.request.ChangePasswordRequest;

/** Operations for a signed-in user changing their password. */
public interface PasswordChangeService {
    void changePassword(Long clientApplicationId, ChangePasswordRequest request);
}

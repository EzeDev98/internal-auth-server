package com.internal.auth.feature.passwordreset.service;

import com.internal.auth.feature.identity.dto.request.ChangePasswordRequest;

/** A signed-in user changing their own password (step 17g, B-02), as opposed to resetting a forgotten one. */
public interface PasswordChangeService {

    /**
     * Checks the current password, applies the same new-password rules as a reset, and stores the
     * new one. A wrong current password is a 400 "Incorrect password." and changes nothing.
     *
     * <p>Sessions are left alone: this service keeps ONE active session per user, and that is the
     * caller's own, so there is no other session to end. When several sessions per user exist, ending
     * the others belongs here.
     */
    void changePassword(Long clientApplicationId, ChangePasswordRequest request);
}

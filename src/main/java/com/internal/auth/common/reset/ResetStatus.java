package com.internal.auth.common.reset;

/** Lifecycle states of a reset OTP or token. */
public enum ResetStatus {
    ACTIVE,
    VERIFIED,
    EXPIRED,
    INVALIDATED
}

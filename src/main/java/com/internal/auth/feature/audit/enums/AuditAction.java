package com.internal.auth.feature.audit.enums;

/**
 * Step 14A - the audit action taxonomy. Deliberately starts with exactly
 * one value: LOGIN_SUCCESS is the only action actually wired to publish an
 * audit event as of this step (see LoginServiceImpl.login()/
 * verifyLoginOtp()). Add a value here only when a real caller is being
 * wired to publish it in the same change - this enum isn't meant to get
 * ahead of what's actually instrumented.
 */
public enum AuditAction {
    LOGIN_SUCCESS
}

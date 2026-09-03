package com.internal.auth.feature.identity.service;

public interface MfaAdminService {
    void setMfaEnabled(String username, boolean enabled);
}

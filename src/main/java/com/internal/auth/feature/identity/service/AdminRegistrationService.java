package com.internal.auth.feature.identity.service;

import com.internal.auth.feature.identity.dto.AdminRegisterRequest;
import com.internal.auth.feature.identity.dto.AdminRegisterResponse;

public interface AdminRegistrationService {
    AdminRegisterResponse register(AdminRegisterRequest request, Long adminClientApplicationId);
}

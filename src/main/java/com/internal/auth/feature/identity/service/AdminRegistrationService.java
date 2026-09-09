package com.internal.auth.feature.identity.service;

import com.internal.auth.feature.identity.dto.request.AdminRegisterRequest;
import com.internal.auth.feature.identity.dto.response.AdminRegisterResponse;

public interface AdminRegistrationService {
    AdminRegisterResponse register(AdminRegisterRequest request, Long adminClientApplicationId);
}

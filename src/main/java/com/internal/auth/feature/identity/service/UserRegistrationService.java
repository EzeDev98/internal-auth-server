package com.internal.auth.feature.identity.service;

import com.internal.auth.feature.identity.dto.request.RegisterRequest;
import com.internal.auth.feature.identity.dto.response.RegisterResponse;

/** Operations for user registration. */
public interface UserRegistrationService {
    RegisterResponse register(RegisterRequest request, Long clientApplicationId);
}

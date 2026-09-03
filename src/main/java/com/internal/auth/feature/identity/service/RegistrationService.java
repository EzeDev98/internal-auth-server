package com.internal.auth.feature.identity.service;

import com.internal.auth.feature.identity.dto.RegisterRequest;
import com.internal.auth.feature.identity.dto.RegisterResponse;

public interface RegistrationService {
    RegisterResponse register(RegisterRequest request);
}

package com.internal.auth.feature.identity.service;

import com.internal.auth.feature.identity.dto.RegisterRequest;
import com.internal.auth.feature.identity.dto.RegisterResponse;

public interface RegistrationService {
    /**
     * @param clientApplicationId the calling app's resolved
     *   client_application_id (see RegistrationController - resolved from
     *   the request's Authorization: Basic clientId:clientSecret header,
     *   multi-tenant redesign). Every uniqueness check and the created
     *   User row itself are scoped to this value.
     */
    RegisterResponse register(RegisterRequest request, Long clientApplicationId);
}

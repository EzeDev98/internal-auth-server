package com.internal.auth.feature.client.service;

import com.internal.auth.feature.client.dto.CreateClientApplicationRequest;
import com.internal.auth.feature.client.dto.CreateClientApplicationResponse;

public interface ClientApplicationService {

    CreateClientApplicationResponse createClient(CreateClientApplicationRequest request);

    /**
     * Verifies a raw client secret against the stored BCrypt hash for the
     * given clientId. Returns false (never throws) for an unknown clientId,
     * a disabled client, or a public client with no secret at all - Step 12
     * (OAuth2 client-credentials grant) is the intended future caller and
     * needs a single boolean, not a reason.
     */
    boolean verifyClientSecret(String clientId, String rawSecret);
}

package com.internal.auth.feature.client.service;

import com.internal.auth.feature.client.dto.CreateClientApplicationRequest;
import com.internal.auth.feature.client.dto.CreateClientApplicationResponse;
import com.internal.auth.feature.client.model.ClientApplication;

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

    /**
     * Verifies a raw client secret the same way verifyClientSecret does,
     * but returns the resolved ClientApplication on success instead of a
     * boolean, and throws InvalidClientCredentialsException on any
     * failure (unknown clientId, disabled client, public client with no
     * secret, wrong secret) rather than returning false. Added for the
     * multi-tenant redesign's registration step, which needs the resolved
     * client_application_id, not just a yes/no.
     */
    ClientApplication authenticateClient(String clientId, String rawSecret);

    /**
     * Parses an "Authorization: Basic base64(clientId:clientSecret)"
     * header and delegates to authenticateClient. Throws
     * InvalidClientCredentialsException for a missing header, a non-Basic
     * scheme, malformed Base64, or a missing ":" separator - same as any
     * other credential failure here, deliberately no distinct message.
     */
    ClientApplication authenticateClientFromBasicAuthHeader(String authorizationHeader);

    /**
     * Resolves an enabled ClientApplication by its public clientId, with
     * no secret verification - for callers already authenticated some
     * other way (e.g. an admin's own JWT) that just need to disambiguate
     * which app a request concerns, not authenticate as that app. Used by
     * UserSessionController's admin session-invalidation endpoint
     * (multi-tenant redesign, sessions step). Throws BadRequestException
     * for an unknown or disabled clientId - not
     * InvalidClientCredentialsException, since no credential is being
     * checked here, just a lookup.
     */
    ClientApplication getEnabledClientByClientId(String clientId);
}

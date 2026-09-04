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

    /**
     * Resolves an app by its internal surrogate id (not the public
     * clientId), for callers that already have a resolved
     * clientApplicationId from an earlier authentication step in the same
     * request and just need read-only details - currently used to get the
     * app's display name for SMS branding (see OtpDeliveryService). Not a
     * credential check. Throws BadRequestException for an unknown id -
     * shouldn't happen in practice, since every caller only ever passes
     * an id that was already resolved from a successful
     * authenticateClientFromBasicAuthHeader call earlier in the request.
     */
    ClientApplication getById(Long id);

    /**
     * Regenerates the client secret for an existing, enabled client
     * application (fixes "no client-secret rotation endpoint - you must
     * create a new client application"), replacing the stored hash
     * immediately - no grace period, the old secret stops working the
     * moment this returns. The generated raw secret is returned exactly
     * once, same as createClient: if this response is lost too, the
     * recovery is calling this again, not registering a whole new
     * client application. Throws BadRequestException for an unknown or
     * disabled clientId, same as getEnabledClientByClientId (which this
     * delegates the lookup to) - not a credential check, since the caller
     * is already an authenticated admin.
     */
    CreateClientApplicationResponse rotateClientSecret(String clientId);
    /**
     * Admin bootstrap (AdminController): returns the reserved internal
     * ClientApplication admin User rows are scoped under
     * ("internal-auth-admin-console" - AppConstant#INTERNAL_ADMIN_CLIENT_ID),
     * creating it on first use if it doesn't exist yet. No manual seeding or
     * migration data required - this deliberately bypasses the
     * @PreAuthorize(Roles.HAS_ADMIN) gate on
     * ClientApplicationController#createClient by never going through that
     * controller at all; the gate lives on that HTTP entry point, not on
     * this service method, so calling this service directly is the intended
     * way past the chicken-and-egg problem for the very first admin. The
     * created row has no client secret (a public/no-secret client) since
     * nothing ever authenticates against it via HTTP Basic.
     */
    ClientApplication getOrCreateInternalAdminClient();

}

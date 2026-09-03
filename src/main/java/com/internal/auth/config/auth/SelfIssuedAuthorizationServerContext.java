package com.internal.auth.config.auth;

import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/**
 * Step 12F - a minimal {@link AuthorizationServerContext} for token minting
 * that happens outside the authorization server's own securityMatcher-scoped
 * filter chain (see AuthorizationServerConfig's
 * authorizationServerSecurityFilterChain, matched only to /oauth2/* and
 * /.well-known/*).
 *
 * <p>Ground truth (javap against spring-security-oauth2-authorization-server
 * 1.2.4, this project's actually-resolved version): the only concrete
 * implementation of this interface in that jar is a private nested class,
 * {@code AuthorizationServerContextFilter.DefaultAuthorizationServerContext}
 * - inaccessible outside that package, and only ever populated by the
 * {@code AuthorizationServerContextFilter} that runs on the securityMatcher-
 * scoped chain above. A request to /api/v1/auth/login goes through
 * WebSecurityConfig's catch-all chain instead, which never runs that filter,
 * so {@code AuthorizationServerContextHolder.getContext()} is not reliably
 * populated there. Since the interface itself is just two methods, this
 * class supplies both directly from beans LoginServiceImpl already has
 * (app.self-issuer-uri and the authorizationServerSettings() bean) rather
 * than depending on the thread-local holder being set by a filter that
 * never runs on this request path.
 */
public class SelfIssuedAuthorizationServerContext implements AuthorizationServerContext {

    private final String issuer;
    private final AuthorizationServerSettings authorizationServerSettings;

    public SelfIssuedAuthorizationServerContext(String issuer, AuthorizationServerSettings authorizationServerSettings) {
        this.issuer = issuer;
        this.authorizationServerSettings = authorizationServerSettings;
    }

    @Override
    public String getIssuer() {
        return issuer;
    }

    @Override
    public AuthorizationServerSettings getAuthorizationServerSettings() {
        return authorizationServerSettings;
    }
}

package com.internal.auth.common.security;

import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/** Authorization server context for minting tokens outside the authorization server filter chain. */
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

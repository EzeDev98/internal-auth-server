package com.internal.auth.testsupport;

import com.internal.auth.common.security.SelfIssuedAuthorizationServerContext;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/** Mints valid self-issued access tokens for tests. */
@TestComponent
@RequiredArgsConstructor
public class TestTokenMinter {

    private static final AuthorizationGrantType LOCAL_LOGIN_GRANT_TYPE =
            new AuthorizationGrantType("local_login");

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2TokenGenerator<OAuth2Token> tokenGenerator;
    private final AuthorizationServerSettings authorizationServerSettings;

    @Value("${app.self-issuer-uri}")
    private String selfIssuerUri;

    public String mintAccessToken(Long clientApplicationId, String username) {
        return mintAccessToken(clientApplicationId, username, List.of());
    }

    public String mintAccessToken(Long clientApplicationId, String username, List<String> roleNames) {
        RegisteredClient registeredClient = registeredClientRepository.findById(String.valueOf(clientApplicationId));
        if (registeredClient == null) {
            throw new IllegalStateException(
                    "No RegisteredClient for client application id " + clientApplicationId
                            + " - persist a ClientApplication row (ClientApplicationTestDataBuilder) before minting a token for it.");
        }

        Collection<GrantedAuthority> authorities = roleNames.stream()
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority(role.toLowerCase(Locale.ROOT)))
                .collect(Collectors.toSet());

        UsernamePasswordAuthenticationToken principal =
                new UsernamePasswordAuthenticationToken(username, null, authorities);
        principal.setDetails(clientApplicationId);

        AuthorizationServerContext context =
                new SelfIssuedAuthorizationServerContext(selfIssuerUri, authorizationServerSettings);

        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(principal)
                .authorizationServerContext(context)
                .authorizedScopes(Set.of())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(LOCAL_LOGIN_GRANT_TYPE)
                .authorizationGrant(principal)
                .build();

        OAuth2Token generated = tokenGenerator.generate(tokenContext);
        if (generated == null) {
            throw new IllegalStateException("Token generator returned null for test user '" + username + "'.");
        }
        return generated.getTokenValue();
    }
}

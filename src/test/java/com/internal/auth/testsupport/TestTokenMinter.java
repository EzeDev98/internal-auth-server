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

/**
 * Mints real, fully valid self-issued access tokens for MockMvc tests -
 * without going through POST /auth/login - by driving the exact same
 * OAuth2TokenGenerator / RegisteredClientRepository / AuthorizationServerSettings
 * beans LoginServiceImpl#mintAccessToken uses in production (same class,
 * same method, see its source for the original this is mirrored from).
 * Only the identity (username, roles, client_application_id) is
 * test-supplied - token construction, RSA signing, and claim-stamping
 * (AuthorizationServerConfig's jwtTokenCustomizer adds "roles", "kid", and
 * "client_application_id") are 100% production code, so a test token is
 * indistinguishable from a real one to every consumer of it
 * (WebSecurityConfig#jwtDecoder, SelfIssuedJwtRolesConverter,
 * AuthenticationHelper).
 *
 * Does NOT persist an OAuth2Authorization row (the oauth2_authorization
 * table) the way a real login does - that table backs the authorization
 * server's own introspection/revocation, not the resource-server JWT
 * decode path this exercises, so it isn't needed for a bearer token to
 * validate correctly here.
 *
 * Requires a ClientApplication row (and therefore a RegisteredClient - see
 * ClientApplicationRegisteredClientRepository) to already exist for the
 * given clientApplicationId - persist one via ClientApplicationTestDataBuilder
 * first, or this throws IllegalStateException.
 */
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

    /** Mints a token for a user with no roles - e.g. a freshly-registered, unverified account. */
    public String mintAccessToken(Long clientApplicationId, String username) {
        return mintAccessToken(clientApplicationId, username, List.of());
    }

    /** Mints a token carrying the given role names, e.g. List.of("create-admin"). */
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
        // Read back by AuthorizationServerConfig's jwtTokenCustomizer to stamp
        // the "client_application_id" claim - see LoginServiceImpl#mintAccessToken.
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

package com.internal.auth.config.auth;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.ZoneOffset;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Step 12A - adapts Step 8's ClientApplication rows into Spring
 * Authorization Server's own RegisteredClient domain object, so the
 * authorization server (AuthorizationServerConfig) recognizes exactly the
 * same client applications that already authenticate via HTTP Basic on
 * /register, /login, etc. (ClientApplicationService). There is
 * deliberately no separate "OAuth2 client" concept to keep in sync -
 * ClientApplication stays the single source of truth for "who is calling
 * this service".
 *
 * <p><b>Grant type decision (confirmed with the project owner for Step
 * 12A):</b> every integrating app (SyncPoint, Notare, future apps) talks
 * to this service server-to-server via HTTP Basic, not a browser redirect,
 * so client_credentials is the default grant when a ClientApplication row's
 * own {@code grantTypes} is empty. If a row already has explicit grant
 * types set (via admin client creation), those are used instead - this is
 * only a fallback, not an override.
 *
 * <p><b>clientSecret mapping:</b> ClientApplication.clientSecretHash is
 * already a BCrypt hash produced by the same PasswordEncoder bean
 * WebSecurityConfig publishes (see that class's javadoc on the credential
 * storage policy). Spring Authorization Server's own client-authentication
 * provider looks up a PasswordEncoder bean from the application context to
 * verify it - since this app only ever publishes the one BCryptPasswordEncoder
 * bean, no re-hashing or prefix ("{bcrypt}") translation is needed here.
 *
 * <p><b>save() is intentionally unsupported.</b> Client creation stays
 * owned by ClientApplicationService#createClient (Step 10D's admin
 * endpoint) - nothing in this app registers a client through the
 * authorization server's own machinery, so there is no legitimate caller
 * of RegisteredClientRepository#save at all. Throwing here makes that
 * explicit instead of silently no-op-ing or writing a row Spring's own
 * client-registration flow would expect to own end-to-end.
 *
 * <p>Step 15A: TokenSettings now sets explicit access/refresh TTLs and
 * disables refresh token reuse (rotation) - see toRegisteredClient() below.
 * ClientSettings (PKCE/consent requirements) is still left at Spring's
 * defaults, since nothing here is authorization_code-based yet.
 *
 * <p>Refresh token TTL now supports a per-client override (Part B):
 * {@code refreshTokenTimeToLive} above uses
 * {@code ClientApplication.refreshTokenTtlDays} when a row has one set,
 * falling back to the global {@code refreshTokenTtlDays} default
 * otherwise - see resolveRefreshTokenTtlDays(). {@code reuseRefreshTokens}
 * stays fixed at {@code false} here regardless: that flag is only read by
 * Spring's own /oauth2/token grant machinery, which this app's custom
 * login/refresh endpoints don't use - UserLoginServiceImpl reads
 * {@code ClientApplication.refreshTokenRotationEnabled} directly instead.
 * A row without "refresh_token" in its own grantTypes still gets a
 * RegisteredClient with these TokenSettings; it just never has a caller
 * that requests a refresh-typed token, since grant enforcement for
 * LoginServiceImpl's in-process minting path is done by that service
 * itself, not by this repository or Spring's filter chain.
 */
@Component
@RequiredArgsConstructor
public class ClientApplicationRegisteredClientRepository implements RegisteredClientRepository {

    private static final Logger log = LoggerFactory.getLogger(ClientApplicationRegisteredClientRepository.class);

    private final ClientApplicationRepository clientApplicationRepository;

    // Field-injected (not constructor, to avoid depending on Lombok copying
    // @Value onto the generated constructor param) - same pattern
    // WebSecurityConfig already uses for its own @Value fields.
    @Value("${app.authorization-server.access-token-ttl-minutes}")
    private long accessTokenTtlMinutes;

    @Value("${app.authorization-server.refresh-token-ttl-days}")
    private long refreshTokenTtlDays;

    @Override
    public void save(RegisteredClient registeredClient) {
        throw new UnsupportedOperationException("Client applications are created via ClientApplicationService#createClient, not through Spring Authorization Server's own registration path.");
    }

    @Override
    public RegisteredClient findById(String id) {
        Long surrogateId;
        try {
            surrogateId = Long.valueOf(id);
        } catch (NumberFormatException e) {
            return null;
        }
        return clientApplicationRepository.findById(surrogateId)
                .filter(ClientApplication::isEnabled)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return clientApplicationRepository.findByClientId(clientId)
                .filter(ClientApplication::isEnabled)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    private RegisteredClient toRegisteredClient(ClientApplication client) {
        Set<AuthorizationGrantType> grantTypes = resolveGrantTypes(client);
        ClientAuthenticationMethod authenticationMethod = client.getClientSecretHash() != null
                ? ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                : ClientAuthenticationMethod.NONE;

        return RegisteredClient.withId(String.valueOf(client.getId()))
                .clientId(client.getClientId())
                .clientIdIssuedAt(client.getCreatedAt() == null ? null : client.getCreatedAt().toInstant(ZoneOffset.UTC))
                .clientSecret(client.getClientSecretHash())
                .clientName(client.getName())
                .clientAuthenticationMethod(authenticationMethod)
                .authorizationGrantTypes(types -> types.addAll(grantTypes))
                .redirectUris(uris -> uris.addAll(client.getRedirectUris()))
                .scopes(scopes -> scopes.addAll(client.getScopes()))
                .clientSettings(ClientSettings.builder().build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(accessTokenTtlMinutes))
                        .refreshTokenTimeToLive(Duration.ofDays(resolveRefreshTokenTtlDays(client)))
                        // Rotation, not reuse: each refresh call is expected to mint
                        // a fresh refresh token and invalidate the one just spent,
                        // rather than letting the same refresh token be replayed
                        // indefinitely until its TTL expires. This flag is only read
                        // by Spring's own /oauth2/token grant machinery though, which
                        // this app's custom login/refresh endpoints don't go through -
                        // UserLoginServiceImpl reads refreshTokenRotationEnabled
                        // directly instead (Part B of the refresh-token-fix doc).
                        .reuseRefreshTokens(false)
                        .build())
                .build();
    }

    /**
     * Part B: per-client override of refresh token lifetime, so a tenant
     * (e.g. an offline-first app that wants a long-lived, non-rotating
     * "session" refresh token) can run its own TTL window without
     * changing the global app.authorization-server.refresh-token-ttl-days
     * default every other client still gets.
     */
    private long resolveRefreshTokenTtlDays(ClientApplication client) {
        return client.getRefreshTokenTtlDays() != null ? client.getRefreshTokenTtlDays() : refreshTokenTtlDays;
    }

    private Set<AuthorizationGrantType> resolveGrantTypes(ClientApplication client) {
        Set<AuthorizationGrantType> resolved = client.getGrantTypes().stream()
                .map(this::resolveGrantType)
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(LinkedHashSet::new));

        if (resolved.isEmpty()) {
            if (!client.getGrantTypes().isEmpty()) {
                log.warn("Client id {} has grantTypes set but none of them were recognized ({}) - falling back to client_credentials",
                        client.getClientId(), client.getGrantTypes());
            }
            resolved.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
        }
        return resolved;
    }

    private AuthorizationGrantType resolveGrantType(String raw) {
        if (raw == null) {
            return null;
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "client_credentials" -> AuthorizationGrantType.CLIENT_CREDENTIALS;
            case "authorization_code" -> AuthorizationGrantType.AUTHORIZATION_CODE;
            case "refresh_token" -> AuthorizationGrantType.REFRESH_TOKEN;
            default -> null;
        };
    }
}
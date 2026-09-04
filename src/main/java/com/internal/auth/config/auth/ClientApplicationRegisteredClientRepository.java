package com.internal.auth.config.auth;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

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
 * <p>Not yet handled (out of scope for 12A, tracked for a later step):
 * ClientSettings/TokenSettings are left at Spring's defaults (no PKCE
 * requirement, no consent requirement, default token TTLs) - irrelevant
 * for client_credentials today, but will need real values once an
 * authorization_code-based app shows up.
 */
@Component
@RequiredArgsConstructor
public class ClientApplicationRegisteredClientRepository implements RegisteredClientRepository {

    private static final Logger log = LoggerFactory.getLogger(ClientApplicationRegisteredClientRepository.class);

    private final ClientApplicationRepository clientApplicationRepository;

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
                .tokenSettings(TokenSettings.builder().build())
                .build();
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

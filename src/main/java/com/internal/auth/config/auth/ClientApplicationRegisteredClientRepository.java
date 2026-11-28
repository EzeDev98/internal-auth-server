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

/** Exposes client applications to Spring Authorization Server as registered clients. */
@Component
@RequiredArgsConstructor
public class ClientApplicationRegisteredClientRepository implements RegisteredClientRepository {

    private static final Logger log = LoggerFactory.getLogger(ClientApplicationRegisteredClientRepository.class);

    private final ClientApplicationRepository clientApplicationRepository;

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
                .redirectUris(uris -> {
                    uris.addAll(client.getRedirectUris());
                    if (uris.isEmpty() && grantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
                        uris.add("http://127.0.0.1/unused-redirect");
                    }
                })
                .scopes(scopes -> scopes.addAll(client.getScopes()))
                .clientSettings(ClientSettings.builder().build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(accessTokenTtlMinutes))
                        .refreshTokenTimeToLive(Duration.ofDays(resolveRefreshTokenTtlDays(client)))
                        .reuseRefreshTokens(false)
                        .build())
                .build();
    }

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

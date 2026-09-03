package com.internal.auth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.UUID;

@Slf4j
@Configuration
public class RestClientConfig {

    private static final String CLIENT_REGISTRATION_ID = "internal-auth";

    @Value("${keycloak.get-token-url}")
    private String keycloakTokenUri;

    @Value("${keycloak.client-id}")
    private String keycloakClientId;

    @Value("${keycloak.client-secret}")
    private String keycloakClientSecret;

    // ─────────────────────────────────────────────────────────────────────────
    //  OAuth2 Client Credentials setup
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Registers this service's Keycloak client credentials.
     * Spring uses this to fetch and cache the Bearer token automatically.
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration registration = ClientRegistration
                .withRegistrationId(CLIENT_REGISTRATION_ID)
                .tokenUri(keycloakTokenUri)
                .clientId(keycloakClientId)
                .clientSecret(keycloakClientSecret)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("openid")
                .build();

        return new InMemoryClientRegistrationRepository(registration);
    }

    /**
     * Manages the OAuth2 authorized client lifecycle — fetching a new token
     * when none exists and refreshing it before expiry.
     *
     * <p>{@link AuthorizedClientServiceOAuth2AuthorizedClientManager} is used
     * (not the standard {@code DefaultOAuth2AuthorizedClientManager}) because
     * this app has no HTTP request context at token-fetch time — tokens are
     * obtained from a scheduler thread, not a web request thread.
     */
    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository) {

        OAuth2AuthorizedClientProvider provider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .clientCredentials()
                        .build();

        AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                        clientRegistrationRepository,
                        new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository)
                );

        manager.setAuthorizedClientProvider(provider);
        return manager;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Interceptors
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Fetches a service-account Bearer token from Keycloak using the Client Credentials
     * grant and attaches it to every outgoing request.
     *
     * <p>Spring caches the token in memory and re-fetches it automatically before
     * expiry, so Keycloak is not called on every HTTP request.
     *
     * <p>{@code OAuth2AuthorizeRequest.principal(CLIENT_REGISTRATION_ID)} uses a
     * fixed string as the principal name. This is correct for client credentials —
     * there is no user; the service itself is the principal.
     */
    private ClientHttpRequestInterceptor oauth2BearerTokenInterceptor(
            OAuth2AuthorizedClientManager authorizedClientManager) {

        return (request, body, execution) -> {
            try {
                OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                        .withClientRegistrationId(CLIENT_REGISTRATION_ID)
                        .principal(CLIENT_REGISTRATION_ID)
                        .build();

                OAuth2AuthorizedClient authorizedClient =
                        authorizedClientManager.authorize(authorizeRequest);

                if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
                    log.error("Failed to obtain service token from Keycloak");
                    throw new IllegalStateException("Unable to obtain service access token");
                }

                request.getHeaders().setBearerAuth(
                        authorizedClient.getAccessToken().getTokenValue()
                );

                log.debug("Service token attached | {} {}", request.getMethod(), request.getURI());

            } catch (Exception ex) {
                log.error("OAuth2 client credentials flow failed: {}", ex.getMessage(), ex);
                throw new IllegalStateException("Service authentication failed", ex);
            }

            return execution.execute(request, body);
        };
    }

    private ClientHttpRequestInterceptor requestIdInterceptor() {
        return (request, body, execution) -> {
            if (request.getHeaders().getFirst("X-Request-ID") == null) {
                request.getHeaders().set("X-Request-ID", UUID.randomUUID().toString());
            }
            return execution.execute(request, body);
        };
    }

    private ClientHttpRequestInterceptor loggingInterceptor() {
        return (request, body, execution) -> {
            long start = System.currentTimeMillis();
            String requestId = request.getHeaders().getFirst("X-Request-ID");

            log.info("[{}] Outgoing: {} {}", requestId, request.getMethod(), request.getURI());

            try {
                var response = execution.execute(request, body);
                log.info("[{}] Response: {} ({}ms)", requestId,
                        response.getStatusCode().value(), System.currentTimeMillis() - start);
                return response;
            } catch (Exception ex) {
                log.error("[{}] Error after {}ms: {}", requestId,
                        System.currentTimeMillis() - start, ex.getMessage(), ex);
                throw ex;
            }
        };
    }
}
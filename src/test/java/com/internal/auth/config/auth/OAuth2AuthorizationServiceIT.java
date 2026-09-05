package com.internal.auth.config.auth;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Step 9E. AuthorizationServerConfig's own javadoc on the
 * authorizationService() bean explains exactly why this matters: a wrong
 * ObjectMapper module registration on JdbcOAuth2AuthorizationService
 * "compiles fine but throws at runtime the first time a real authorization
 * round-trips through the database" - not something a mocked collaborator
 * can ever catch. This exercises the real bean, against real Postgres
 * (V21's oauth2_authorization table), saving and reading an authorization
 * back through both findById and findByToken.
 */
class OAuth2AuthorizationServiceIT extends IntegrationTestBase {

    @Autowired
    private OAuth2AuthorizationService authorizationService;
    @Autowired
    private RegisteredClientRepository registeredClientRepository;
    @Autowired
    private ClientApplicationRepository clientApplicationRepository;

    @Test
    void savedAuthorization_roundTripsThroughFindByIdAndFindByToken_withAccessTokenRefreshTokenAndCustomAttributes() {
        ClientApplication client = clientApplicationRepository.save(
                ClientApplicationTestDataBuilder.aClientApplication().build());
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(client.getClientId());

        Instant issuedAt = Instant.now();
        String accessTokenValue = "access-token-" + issuedAt.toEpochMilli();
        String refreshTokenValue = "refresh-token-" + issuedAt.toEpochMilli();

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(UUID.randomUUID().toString())
                .principalName("some-service-account")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizedScopes(Set.of("openid"))
                .attribute("test-claim", "test-value")
                .accessToken(new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER,
                        accessTokenValue,
                        issuedAt,
                        issuedAt.plusSeconds(3600),
                        Set.of("openid")))
                .refreshToken(new OAuth2RefreshToken(
                        refreshTokenValue,
                        issuedAt,
                        issuedAt.plusSeconds(86400)))
                .build();

        authorizationService.save(authorization);

        OAuth2Authorization foundById = authorizationService.findById(authorization.getId());
        assertThat(foundById).isNotNull();
        assertThat(foundById.getPrincipalName()).isEqualTo("some-service-account");
        assertThat(foundById.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
        String testClaimAttribute = foundById.getAttribute("test-claim");
        assertThat(testClaimAttribute).isEqualTo("test-value");
        assertThat(foundById.getAccessToken()).isNotNull();
        OAuth2AccessToken persistedAccessToken = foundById.getAccessToken().getToken();
        assertThat(persistedAccessToken.getTokenValue()).isEqualTo(accessTokenValue);
        assertThat(foundById.getRefreshToken()).isNotNull();
        OAuth2RefreshToken persistedRefreshToken = foundById.getRefreshToken().getToken();
        assertThat(persistedRefreshToken.getTokenValue()).isEqualTo(refreshTokenValue);

        OAuth2Authorization foundByAccessToken =
                authorizationService.findByToken(accessTokenValue, OAuth2TokenType.ACCESS_TOKEN);
        assertThat(foundByAccessToken).isNotNull();
        assertThat(foundByAccessToken.getId()).isEqualTo(authorization.getId());

        OAuth2Authorization foundByRefreshToken =
                authorizationService.findByToken(refreshTokenValue, OAuth2TokenType.REFRESH_TOKEN);
        assertThat(foundByRefreshToken).isNotNull();
        assertThat(foundByRefreshToken.getId()).isEqualTo(authorization.getId());
    }
}

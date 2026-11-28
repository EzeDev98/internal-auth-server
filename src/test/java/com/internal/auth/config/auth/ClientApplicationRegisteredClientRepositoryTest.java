package com.internal.auth.config.auth;

import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/** Unit tests for ClientApplicationRegisteredClientRepository. */
class ClientApplicationRegisteredClientRepositoryTest {

    private final ClientApplicationRepository clientApplicationRepository = mock(ClientApplicationRepository.class);

    private final ClientApplicationRegisteredClientRepository repository =
            new ClientApplicationRegisteredClientRepository(clientApplicationRepository);

    @Test
    void save_alwaysThrowsUnsupportedOperationException_andNeverTouchesTheRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId("1")
                .clientId("some-client")
                .clientSecret("irrelevant")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();

        assertThatThrownBy(() -> repository.save(registeredClient))
                .isInstanceOf(UnsupportedOperationException.class)
                .hasMessageContaining("ClientApplicationService#createClient");

        verifyNoInteractions(clientApplicationRepository);
    }
}

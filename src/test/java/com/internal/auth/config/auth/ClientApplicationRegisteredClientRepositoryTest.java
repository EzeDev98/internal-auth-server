package com.internal.auth.config.auth;

import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Step 11C (unit half). ClientApplicationRegisteredClientRepository's own
 * javadoc on save() explains why it must never silently succeed or write a
 * row: client creation is owned end-to-end by
 * ClientApplicationService#createClient, so there is no legitimate caller
 * of RegisteredClientRepository#save at all. This locks in the throw
 * itself and confirms it fires before ever touching
 * ClientApplicationRepository. ClientApplicationRegisteredClientRepositoryIT
 * covers the other half of Step 11C - that Spring Security's own internals
 * never call save() during ordinary client_credentials token issuance.
 */
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

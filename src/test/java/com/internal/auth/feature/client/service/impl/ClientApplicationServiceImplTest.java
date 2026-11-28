package com.internal.auth.feature.client.service.impl;

import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.common.security.AuthenticationHelper;
import com.internal.auth.common.util.SecretEncryptionService;
import com.internal.auth.feature.audit.event.ClientSettingsChangedEvent;
import com.internal.auth.feature.client.dto.ClientApplicationDetailResponse;
import com.internal.auth.feature.client.dto.CreateClientApplicationRequest;
import com.internal.auth.feature.client.dto.UpdateClientApplicationRequest;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for client application session settings in ClientApplicationServiceImpl. */
class ClientApplicationServiceImplTest {

    private final ClientApplicationRepository repository = mock(ClientApplicationRepository.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final SecretEncryptionService secretEncryptionService = mock(SecretEncryptionService.class);
    private final ApplicationEventPublisher eventPublisher = mock(ApplicationEventPublisher.class);
    private final AuthenticationHelper authenticationHelper = mock(AuthenticationHelper.class);

    private final ClientApplicationServiceImpl service = new ClientApplicationServiceImpl(
            repository, passwordEncoder, secretEncryptionService, eventPublisher, authenticationHelper);

    private ClientApplication client;

    @BeforeEach
    void setUp() {
        client = new ClientApplication();
        client.setId(7L);
        client.setClientId("pay-app");
        client.setName("Offline Pay");
        client.setGrantTypes(new HashSet<>(Set.of("authorization_code", "refresh_token")));
        when(repository.findByClientId("pay-app")).thenReturn(Optional.of(client));
        when(repository.save(any(ClientApplication.class))).thenAnswer(returnsFirstArg());
        when(authenticationHelper.getCurrentUsername()).thenReturn("admin.user");
    }

    @Test
    void update_enablingPersistentToken_savesTheSettingsAndPublishesAnAuditEvent() {
        ClientApplicationDetailResponse response = service.updateClient("pay-app", persistent(60, 90));

        assertThat(response.isRefreshTokenRotationEnabled()).isFalse();
        assertThat(response.getRefreshTokenTtlDays()).isEqualTo(60);
        assertThat(response.getRefreshTokenMaxLifetimeDays()).isEqualTo(90);

        ClientSettingsChangedEvent event = publishedEvent();
        assertThat(event.getActorUsername()).isEqualTo("admin.user");
        assertThat(event.getClientApplicationId()).isEqualTo(7L);
        assertThat(event.getDescription())
                .contains("rotationEnabled=true, refreshTokenTtlDays=null, refreshTokenMaxLifetimeDays=null")
                .contains("rotationEnabled=false, refreshTokenTtlDays=60, refreshTokenMaxLifetimeDays=90");
    }

    @Test
    void update_switchingBackToRotation_clearsTheTtlAndTheCap() {
        client.setRefreshTokenRotationEnabled(false);
        client.setRefreshTokenTtlDays(60);
        client.setRefreshTokenMaxLifetimeDays(90);
        UpdateClientApplicationRequest request = new UpdateClientApplicationRequest();
        request.setRefreshTokenRotationEnabled(true);

        ClientApplicationDetailResponse response = service.updateClient("pay-app", request);

        assertThat(response.isRefreshTokenRotationEnabled()).isTrue();
        assertThat(response.getRefreshTokenTtlDays()).isNull();
        assertThat(response.getRefreshTokenMaxLifetimeDays()).isNull();
    }

    @Test
    void update_persistentWithBlankCap_removesAnExistingCap() {
        client.setRefreshTokenRotationEnabled(false);
        client.setRefreshTokenTtlDays(60);
        client.setRefreshTokenMaxLifetimeDays(90);

        ClientApplicationDetailResponse response = service.updateClient("pay-app", persistent(60, null));

        assertThat(response.getRefreshTokenMaxLifetimeDays()).isNull();
    }

    @Test
    void update_onlyTheName_publishesNoAuditEvent() {
        UpdateClientApplicationRequest request = new UpdateClientApplicationRequest();
        request.setName("Offline Pay v2");

        service.updateClient("pay-app", request);

        verify(eventPublisher, never()).publishEvent(any(Object.class));
    }

    @Test
    void update_ttlBelowOneDay_isRejected() {
        assertRejected(persistent(0, null), "must be between 1 and 365");
    }

    @Test
    void update_ttlAbove365Days_isRejected() {
        assertRejected(persistent(366, null), "must be between 1 and 365");
    }

    @Test
    void update_capBelowTheTtl_isRejected() {
        assertRejected(persistent(60, 30), "refreshTokenMaxLifetimeDays must be between");
    }

    @Test
    void update_capAbove3650Days_isRejected() {
        assertRejected(persistent(60, 3651), "refreshTokenMaxLifetimeDays must be between");
    }

    @Test
    void update_persistentWithoutATtl_isRejected() {
        UpdateClientApplicationRequest request = new UpdateClientApplicationRequest();
        request.setRefreshTokenRotationEnabled(false);

        assertRejected(request, "refreshTokenTtlDays is required");
    }

    @Test
    void update_ttlSuppliedWhileRotationIsOn_isRejected() {
        UpdateClientApplicationRequest request = new UpdateClientApplicationRequest();
        request.setRefreshTokenRotationEnabled(true);
        request.setRefreshTokenTtlDays(60);

        assertRejected(request, "only apply when refreshTokenRotationEnabled is false");
    }

    @Test
    void update_persistentOnAClientWithoutTheRefreshTokenGrant_isRejected() {
        client.setGrantTypes(new HashSet<>(Set.of("authorization_code")));

        assertRejected(persistent(60, null), "requires the client to have the refresh_token grant type");
    }

    @Test
    void update_revokeOff_isSavedAndAudited() {
        UpdateClientApplicationRequest request = new UpdateClientApplicationRequest();
        request.setRevokePriorSessionsOnLogin(false);

        ClientApplicationDetailResponse response = service.updateClient("pay-app", request);

        assertThat(response.isRevokePriorSessionsOnLogin()).isFalse();
        assertThat(publishedEvent().getDescription())
                .contains("revokePriorSessionsOnLogin=true")
                .contains("revokePriorSessionsOnLogin=false");
    }

    @Test
    void update_revokeLeftOut_keepsTheExistingValue() {
        client.setRevokePriorSessionsOnLogin(false);
        UpdateClientApplicationRequest request = new UpdateClientApplicationRequest();
        request.setName("Offline Pay v2");

        ClientApplicationDetailResponse response = service.updateClient("pay-app", request);

        assertThat(response.isRevokePriorSessionsOnLogin()).isFalse();
    }

    @Test
    void update_grantTypes_replacesTheSetAndIsAudited() {
        UpdateClientApplicationRequest request = new UpdateClientApplicationRequest();
        request.setGrantTypes(Set.of("authorization_code"));

        ClientApplicationDetailResponse response = service.updateClient("pay-app", request);

        assertThat(response.getGrantTypes()).containsExactly("authorization_code");
        assertThat(publishedEvent().getDescription())
                .contains("grantTypes=[authorization_code, refresh_token]")
                .contains("grantTypes=[authorization_code]");
    }

    @Test
    void update_emptyGrantTypes_isRejected() {
        UpdateClientApplicationRequest request = new UpdateClientApplicationRequest();
        request.setGrantTypes(Set.of());

        assertRejected(request, "At least one grant type is required");
    }

    @Test
    void update_unknownGrantType_isRejected() {
        UpdateClientApplicationRequest request = new UpdateClientApplicationRequest();
        request.setGrantTypes(Set.of("authorization_code", "password"));

        assertRejected(request, "Unsupported grant type: password");
    }

    @Test
    void update_removingRefreshTokenGrantFromAPersistentClient_isRejected() {
        client.setRefreshTokenRotationEnabled(false);
        client.setRefreshTokenTtlDays(60);
        UpdateClientApplicationRequest request = new UpdateClientApplicationRequest();
        request.setGrantTypes(Set.of("authorization_code"));

        assertRejected(request, "Turn off the persistent refresh token before removing the refresh_token grant type");
    }

    @Test
    void update_removingRefreshTokenGrantWhileTurningPersistentOff_isAllowed() {
        client.setRefreshTokenRotationEnabled(false);
        client.setRefreshTokenTtlDays(60);
        UpdateClientApplicationRequest request = new UpdateClientApplicationRequest();
        request.setRefreshTokenRotationEnabled(true);
        request.setGrantTypes(Set.of("authorization_code"));

        ClientApplicationDetailResponse response = service.updateClient("pay-app", request);

        assertThat(response.isRefreshTokenRotationEnabled()).isTrue();
        assertThat(response.getGrantTypes()).containsExactly("authorization_code");
    }

    @Test
    void create_defaultsRevokeToOn_andAuditsTheInitialSettings() {
        when(passwordEncoder.encode(anyString())).thenReturn("hash");
        when(secretEncryptionService.encrypt(anyString())).thenReturn("encrypted");
        CreateClientApplicationRequest request = new CreateClientApplicationRequest();
        request.setClientId("new-app");
        request.setName("New App");
        request.setGrantTypes(Set.of("refresh_token"));
        request.setRefreshTokenRotationEnabled(false);
        request.setRefreshTokenTtlDays(60);

        service.createClient(request);

        ArgumentCaptor<ClientApplication> saved = ArgumentCaptor.forClass(ClientApplication.class);
        verify(repository).save(saved.capture());
        assertThat(saved.getValue().isRevokePriorSessionsOnLogin()).isTrue();
        assertThat(saved.getValue().isRefreshTokenRotationEnabled()).isFalse();
        assertThat(publishedEvent().getDescription())
                .startsWith("Client new-app created with rotationEnabled=false, refreshTokenTtlDays=60");
    }

    private static UpdateClientApplicationRequest persistent(Integer ttlDays, Integer maxLifetimeDays) {
        UpdateClientApplicationRequest request = new UpdateClientApplicationRequest();
        request.setRefreshTokenRotationEnabled(false);
        request.setRefreshTokenTtlDays(ttlDays);
        request.setRefreshTokenMaxLifetimeDays(maxLifetimeDays);
        return request;
    }

    private void assertRejected(UpdateClientApplicationRequest request, String messagePart) {
        assertThatThrownBy(() -> service.updateClient("pay-app", request))
                .isInstanceOfSatisfying(BadRequestException.class, ex -> assertThat(ex.getMessage()).contains(messagePart));

        verify(repository, never()).save(any(ClientApplication.class));
        verify(eventPublisher, never()).publishEvent(any(Object.class));
    }

    private ClientSettingsChangedEvent publishedEvent() {
        ArgumentCaptor<ClientSettingsChangedEvent> captor = ArgumentCaptor.forClass(ClientSettingsChangedEvent.class);
        verify(eventPublisher).publishEvent(captor.capture());
        return captor.getValue();
    }
}

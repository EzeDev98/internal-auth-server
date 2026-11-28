package com.internal.auth.feature.signingkey.service.impl;

import com.internal.auth.common.util.SecretEncryptionService;
import com.internal.auth.feature.signingkey.enums.SigningKeyStatus;
import com.internal.auth.feature.signingkey.model.SigningKey;
import com.internal.auth.feature.signingkey.repository.SigningKeyRepository;
import com.internal.auth.testsupport.builder.SigningKeyTestDataBuilder;
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for SigningKeyServiceImpl. */
class SigningKeyServiceImplTest {

    private static final String TEST_ENCRYPTION_KEY = "iak3c/+SZanL/YrmpeN6g+bPWpaiOWm6VMng3kZ9Jlk=";

    private final SigningKeyRepository signingKeyRepository = mock(SigningKeyRepository.class);
    private SecretEncryptionService secretEncryptionService;
    private SigningKeyServiceImpl service;

    @BeforeEach
    void setUp() {
        secretEncryptionService = new SecretEncryptionService();
        ReflectionTestUtils.setField(secretEncryptionService, "base64Key", TEST_ENCRYPTION_KEY);
        secretEncryptionService.init();

        service = new SigningKeyServiceImpl(signingKeyRepository, secretEncryptionService);
    }

    @Test
    void init_repoEmptyAndNoConfiguredPem_generatesAndPersistsANewCurrentActiveKey() {
        when(signingKeyRepository.count()).thenReturn(0L);
        ArgumentCaptor<SigningKey> captor = ArgumentCaptor.forClass(SigningKey.class);
        when(signingKeyRepository.save(captor.capture())).thenAnswer(inv -> inv.getArgument(0));

        service.init();

        SigningKey saved = captor.getValue();
        assertThat(saved.isCurrent()).isTrue();
        assertThat(saved.getStatus()).isEqualTo(SigningKeyStatus.ACTIVE);
        assertThat(saved.getKid()).isNotBlank();
        assertThat(saved.getEncryptedPrivateKey()).isNotBlank();
    }

    @Test
    void init_persistedPrivateKey_isActuallyEncryptedAtRest_andDecryptsBackToAValidPemKey() {
        when(signingKeyRepository.count()).thenReturn(0L);
        ArgumentCaptor<SigningKey> captor = ArgumentCaptor.forClass(SigningKey.class);
        when(signingKeyRepository.save(captor.capture())).thenAnswer(inv -> inv.getArgument(0));

        service.init();

        String storedCiphertext = captor.getValue().getEncryptedPrivateKey();
        String decryptedBase64Pem = secretEncryptionService.decrypt(storedCiphertext);
        assertThat(storedCiphertext).isNotEqualTo(decryptedBase64Pem);
        String pem = new String(Base64.getDecoder().decode(decryptedBase64Pem), StandardCharsets.UTF_8);
        assertThat(pem).contains("-----BEGIN PRIVATE KEY-----").contains("-----END PRIVATE KEY-----");
    }

    @Test
    void init_repoAlreadyHasKeys_doesNotBootstrapAnything() {
        when(signingKeyRepository.count()).thenReturn(1L);

        service.init();

        verify(signingKeyRepository, never()).save(any());
    }

    @Test
    void init_repoEmptyWithAConfiguredPem_seedsFromThatExactKeyRatherThanGeneratingANewOne() {
        KeyPair configuredKeyPair = generateRsaKeyPair();
        String configuredPemBase64 = toPemBase64(configuredKeyPair);
        ReflectionTestUtils.setField(service, "bootstrapSigningKeyPemBase64", configuredPemBase64);
        when(signingKeyRepository.count()).thenReturn(0L);
        ArgumentCaptor<SigningKey> captor = ArgumentCaptor.forClass(SigningKey.class);
        when(signingKeyRepository.save(captor.capture())).thenAnswer(inv -> inv.getArgument(0));

        service.init();

        String decryptedBase64Pem = secretEncryptionService.decrypt(captor.getValue().getEncryptedPrivateKey());
        assertThat(decryptedBase64Pem).isEqualTo(configuredPemBase64);
    }

    @Test
    void getJwkSet_buildsFromPersistedActiveKeys_andCachesTheResultAcrossRepeatedCalls() {
        SigningKey activeKey = SigningKeyTestDataBuilder.aSigningKey()
                .withKid("kid-1")
                .asCurrent()
                .withEncryptedPrivateKey(secretEncryptionService.encrypt(toPemBase64(generateRsaKeyPair())))
                .build();
        when(signingKeyRepository.findByStatus(SigningKeyStatus.ACTIVE)).thenReturn(List.of(activeKey));

        JWKSet first = service.getJwkSet();
        JWKSet second = service.getJwkSet();

        assertThat(first.getKeys()).hasSize(1);
        assertThat(first.getKeyByKeyId("kid-1")).isNotNull();
        assertThat(second).isSameAs(first);
        verify(signingKeyRepository, times(1)).findByStatus(SigningKeyStatus.ACTIVE);
    }

    @Test
    void getCurrentKid_returnsTheKidOfTheRowMarkedCurrent() {
        SigningKey currentKey = SigningKeyTestDataBuilder.aSigningKey()
                .withKid("current-kid")
                .asCurrent()
                .withEncryptedPrivateKey(secretEncryptionService.encrypt(toPemBase64(generateRsaKeyPair())))
                .build();
        when(signingKeyRepository.findByStatus(SigningKeyStatus.ACTIVE)).thenReturn(List.of(currentKey));

        assertThat(service.getCurrentKid()).isEqualTo("current-kid");
    }

    @Test
    void rotate_demotesThePreviousCurrentKey_andPersistsAFreshCurrentKey() {
        SigningKey previousCurrent = SigningKeyTestDataBuilder.aSigningKey().withKid("old-kid").asCurrent().build();
        when(signingKeyRepository.findByCurrentTrue()).thenReturn(Optional.of(previousCurrent));
        when(signingKeyRepository.findByStatusAndCurrentFalseAndCreatedAtBefore(eq(SigningKeyStatus.ACTIVE), any()))
                .thenReturn(List.of());
        ArgumentCaptor<SigningKey> savedCaptor = ArgumentCaptor.forClass(SigningKey.class);
        when(signingKeyRepository.save(savedCaptor.capture())).thenAnswer(inv -> inv.getArgument(0));

        SigningKey rotated = service.rotate();

        assertThat(previousCurrent.isCurrent()).isFalse();
        assertThat(rotated.isCurrent()).isTrue();
        assertThat(rotated.getStatus()).isEqualTo(SigningKeyStatus.ACTIVE);
        assertThat(rotated.getKid()).isNotEqualTo("old-kid");
        assertThat(savedCaptor.getAllValues()).contains(previousCurrent, rotated);
    }

    @Test
    void rotate_retiresKeysPastTheGracePeriodCutoff_flippingThemToRetiredWithATimestamp() {
        when(signingKeyRepository.findByCurrentTrue()).thenReturn(Optional.empty());
        SigningKey staleKey = SigningKeyTestDataBuilder.aSigningKey().withKid("stale-kid").withStatus(SigningKeyStatus.ACTIVE).build();
        when(signingKeyRepository.findByStatusAndCurrentFalseAndCreatedAtBefore(eq(SigningKeyStatus.ACTIVE), any()))
                .thenReturn(List.of(staleKey));
        when(signingKeyRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        service.rotate();

        verify(signingKeyRepository).saveAll(List.of(staleKey));
        assertThat(staleKey.getStatus()).isEqualTo(SigningKeyStatus.RETIRED);
        assertThat(staleKey.getRetiredAt()).isNotNull();
    }

    @Test
    void jwkSet_includesAGracePeriodOldKeyAlongsideTheNewCurrentOne_soTokensSignedByEitherStillVerify() {
        SigningKey oldStillActive = SigningKeyTestDataBuilder.aSigningKey()
                .withKid("old-kid")
                .withStatus(SigningKeyStatus.ACTIVE)
                .withEncryptedPrivateKey(secretEncryptionService.encrypt(toPemBase64(generateRsaKeyPair())))
                .build();
        SigningKey newCurrent = SigningKeyTestDataBuilder.aSigningKey()
                .withKid("new-kid")
                .asCurrent()
                .withEncryptedPrivateKey(secretEncryptionService.encrypt(toPemBase64(generateRsaKeyPair())))
                .build();
        when(signingKeyRepository.findByStatus(SigningKeyStatus.ACTIVE)).thenReturn(List.of(oldStillActive, newCurrent));

        JWKSet jwkSet = service.getJwkSet();

        assertThat(jwkSet.getKeyByKeyId("old-kid")).isNotNull();
        assertThat(jwkSet.getKeyByKeyId("new-kid")).isNotNull();
        assertThat(service.getCurrentKid()).isEqualTo("new-kid");
    }

    @Test
    void jwkSet_noLongerIncludesAKey_onceItHasBeenRetiredPastTheGracePeriod() {
        SigningKey stillCurrent = SigningKeyTestDataBuilder.aSigningKey()
                .withKid("new-kid")
                .asCurrent()
                .withEncryptedPrivateKey(secretEncryptionService.encrypt(toPemBase64(generateRsaKeyPair())))
                .build();
        when(signingKeyRepository.findByStatus(SigningKeyStatus.ACTIVE)).thenReturn(List.of(stillCurrent));

        JWKSet jwkSet = service.getJwkSet();

        assertThat(jwkSet.getKeyByKeyId("old-kid")).isNull();
        assertThat(jwkSet.getKeyByKeyId("new-kid")).isNotNull();
    }

    private static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String toPemBase64(KeyPair keyPair) {
        String base64Der = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN PRIVATE KEY-----\n");
        for (int i = 0; i < base64Der.length(); i += 64) {
            pem.append(base64Der, i, Math.min(i + 64, base64Der.length())).append("\n");
        }
        pem.append("-----END PRIVATE KEY-----\n");
        return Base64.getEncoder().encodeToString(pem.toString().getBytes(StandardCharsets.UTF_8));
    }
}

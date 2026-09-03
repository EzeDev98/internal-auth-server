package com.internal.auth.feature.signingkey.service.impl;

import com.internal.auth.common.constant.AppConstant;
import com.internal.auth.common.util.SecretEncryptionService;
import com.internal.auth.feature.signingkey.enums.SigningKeyStatus;
import com.internal.auth.feature.signingkey.model.SigningKey;
import com.internal.auth.feature.signingkey.repository.SigningKeyRepository;
import com.internal.auth.feature.signingkey.service.SigningKeyService;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Step 14D. Owns all JWT signing-key material: generation, PEM encode/decode,
 * persistence (signing_key table, V16), the live JWKSet cache, and rotation.
 * AuthorizationServerConfig's jwkSource()/jwtTokenCustomizer() beans are thin
 * adapters over this class.
 *
 * The decodePemRsaKey/computeKeyId logic below is carried over unchanged
 * from AuthorizationServerConfig's pre-14D single-key implementation (same
 * Base64(PEM) format, same SHA-256-derived kid) - only the persistence and
 * multi-key cache layer around it is new.
 *
 * Step 14E: the PEM string is now encrypted (SecretEncryptionService)
 * before it's ever written to signingKeyRepository, and decrypted
 * immediately after reading a row back - encodeToPemBase64/decodePemRsaKey
 * below never see anything but plaintext PEM; encryption is applied only
 * at the persistNewKey/rebuildCache boundary where a row crosses into or
 * out of the database.
 */
@Service
@RequiredArgsConstructor
public class SigningKeyServiceImpl implements SigningKeyService {

    private static final Logger log = LoggerFactory.getLogger(SigningKeyServiceImpl.class);

    private final SigningKeyRepository signingKeyRepository;
    private final SecretEncryptionService secretEncryptionService;

    @Value("${app.authorization-server.signing-key-pem}")
    private String bootstrapSigningKeyPemBase64;

    private volatile JWKSet cachedJwkSet;
    private volatile String cachedCurrentKid;

    @PostConstruct
    public void init() {
        bootstrapIfEmpty();
    }

    @Override
    public synchronized JWKSet getJwkSet() {
        if (cachedJwkSet == null) {
            rebuildCache();
        }
        return cachedJwkSet;
    }

    @Override
    public synchronized String getCurrentKid() {
        if (cachedCurrentKid == null) {
            rebuildCache();
        }
        return cachedCurrentKid;
    }

    @Override
    @Transactional
    public synchronized SigningKey rotate() {
        KeyPair newKeyPair = generateRsaKeyPair();
        signingKeyRepository.findByCurrentTrue().ifPresent(previous -> {
            previous.setCurrent(false);
            signingKeyRepository.save(previous);
        });
        SigningKey newKey = persistNewKey(newKeyPair, true);
        retireStaleKeys();
        invalidateCache();
        log.info("Rotated signing key. New current kid: {}", newKey.getKid());
        return newKey;
    }

    @Transactional
    protected void bootstrapIfEmpty() {
        if (signingKeyRepository.count() > 0) {
            return;
        }
        KeyPair keyPair;
        if (bootstrapSigningKeyPemBase64 == null || bootstrapSigningKeyPemBase64.isBlank()) {
            log.warn("No persisted signing key exists and app.authorization-server.signing-key-pem is not set - "
                    + "generating and persisting a brand new RSA key now. This happens once; from this boot "
                    + "forward the key survives restarts (unlike the pre-Step-14D fallback).");
            keyPair = generateRsaKeyPair();
        } else {
            log.info("Seeding signing_key table from app.authorization-server.signing-key-pem for the first time.");
            keyPair = decodePemRsaKey(bootstrapSigningKeyPemBase64);
        }
        persistNewKey(keyPair, true);
    }

    private SigningKey persistNewKey(KeyPair keyPair, boolean current) {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        SigningKey entity = new SigningKey();
        entity.setKid(computeKeyId(publicKey));
        entity.setEncryptedPrivateKey(secretEncryptionService.encrypt(encodeToPemBase64(keyPair.getPrivate())));
        entity.setCurrent(current);
        entity.setStatus(SigningKeyStatus.ACTIVE);
        return signingKeyRepository.save(entity);
    }

    private void retireStaleKeys() {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(AppConstant.SIGNING_KEY_GRACE_PERIOD_DAYS);
        List<SigningKey> stale = signingKeyRepository.findByStatusAndCurrentFalseAndCreatedAtBefore(SigningKeyStatus.ACTIVE, cutoff);
        for (SigningKey key : stale) {
            key.setStatus(SigningKeyStatus.RETIRED);
            key.setRetiredAt(LocalDateTime.now());
        }
        signingKeyRepository.saveAll(stale);
    }

    private void rebuildCache() {
        List<SigningKey> activeKeys = signingKeyRepository.findByStatus(SigningKeyStatus.ACTIVE);
        List<JWK> rsaKeys = new ArrayList<>();
        String currentKid = null;
        for (SigningKey key : activeKeys) {
            KeyPair keyPair = decodePemRsaKey(secretEncryptionService.decrypt(key.getEncryptedPrivateKey()));
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            RSAKey rsaKey = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(key.getKid())
                    .build();
            rsaKeys.add(rsaKey);
            if (key.isCurrent()) {
                currentKid = key.getKid();
            }
        }
        cachedJwkSet = new JWKSet(rsaKeys);
        cachedCurrentKid = currentKid;
    }

    private synchronized void invalidateCache() {
        cachedJwkSet = null;
        cachedCurrentKid = null;
    }

    private static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Failed to generate a new RSA signing key", ex);
        }
    }

    private static KeyPair decodePemRsaKey(String base64EncodedPem) {
        String pem;
        try {
            pem = new String(Base64.getDecoder().decode(base64EncodedPem), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Stored signing key is not valid Base64", e);
        }

        String strippedBase64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] der;
        try {
            der = Base64.getDecoder().decode(strippedBase64);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Stored signing key did not decode to a valid PEM body", e);
        }

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(der));
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent());
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            return new KeyPair(publicKey, privateKey);
        } catch (GeneralSecurityException | ClassCastException e) {
            throw new IllegalStateException("Stored signing key must be a PKCS#8-encoded RSA private key", e);
        }
    }

    private static String encodeToPemBase64(PrivateKey privateKey) {
        String base64Der = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN PRIVATE KEY-----\n");
        for (int i = 0; i < base64Der.length(); i += 64) {
            pem.append(base64Der, i, Math.min(i + 64, base64Der.length())).append("\n");
        }
        pem.append("-----END PRIVATE KEY-----\n");
        return Base64.getEncoder().encodeToString(pem.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static String computeKeyId(RSAPublicKey publicKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(publicKey.getEncoded());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            return UUID.randomUUID().toString();
        }
    }
}

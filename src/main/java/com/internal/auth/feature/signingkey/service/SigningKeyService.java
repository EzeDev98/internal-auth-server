package com.internal.auth.feature.signingkey.service;

import com.internal.auth.feature.signingkey.model.SigningKey;
import com.nimbusds.jose.jwk.JWKSet;

import java.util.List;

/** Operations for managing JWT signing keys. */
@org.springframework.modulith.NamedInterface
public interface SigningKeyService {

    JWKSet getJwkSet();

    String getCurrentKid();

    SigningKey rotate();

    List<SigningKey> listKeys();
}

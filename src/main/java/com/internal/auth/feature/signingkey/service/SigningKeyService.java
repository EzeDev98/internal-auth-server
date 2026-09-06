package com.internal.auth.feature.signingkey.service;

import com.internal.auth.feature.signingkey.model.SigningKey;
import com.nimbusds.jose.jwk.JWKSet;

@org.springframework.modulith.NamedInterface
public interface SigningKeyService {

    JWKSet getJwkSet();

    String getCurrentKid();

    SigningKey rotate();
}

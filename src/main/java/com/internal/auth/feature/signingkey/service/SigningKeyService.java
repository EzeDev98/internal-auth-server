package com.internal.auth.feature.signingkey.service;

import com.internal.auth.feature.signingkey.model.SigningKey;
import com.nimbusds.jose.jwk.JWKSet;

import java.util.List;

@org.springframework.modulith.NamedInterface
public interface SigningKeyService {

    JWKSet getJwkSet();

    String getCurrentKid();

    SigningKey rotate();

    // Step 11A: audit list for the Settings - Signing keys panel, newest
    // first - the panel needs to show the current key (and its history)
    // before a rotate, which nothing upstream exposed until now.
    List<SigningKey> listKeys();
}

package com.internal.auth.feature.signingkey.enums;

/**
 * Step 14D. ACTIVE keys are the ones in the live JWKSet (available for
 * verification; at most one of them is also the current signing key - see
 * SigningKey#current). RETIRED keys are kept as rows for audit history but
 * dropped from the JWKSet - a token still bearing a RETIRED key's kid fails
 * verification.
 */
public enum SigningKeyStatus {
    ACTIVE,
    RETIRED
}

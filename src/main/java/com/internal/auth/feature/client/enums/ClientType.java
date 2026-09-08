package com.internal.auth.feature.client.enums;

/**
 * Step 2B (React Admin Client plan v4): not a stored column - derived from
 * whether ClientApplication.clientSecretHash is null (PUBLIC) or present
 * (CONFIDENTIAL). Exists purely as a readable filter/response value for
 * the admin client-application directory.
 */
public enum ClientType {
    PUBLIC,
    CONFIDENTIAL
}

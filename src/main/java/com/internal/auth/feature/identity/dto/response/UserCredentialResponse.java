package com.internal.auth.feature.identity.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * Backs GET ${app.title}/users/{username}/credentials - the Users - Detail
 * Credentials tab. This app only ever stores one credential per user (a
 * BCrypt password hash on User.password - see User's class Javadoc), so
 * unlike Keycloak's own multi-credential model this is a single object,
 * not a list. `type` is always "password" today; kept as a field rather
 * than hardcoded client-side in case a second credential type is ever
 * added. `createdAt` is User.passwordChangedAt when the password has been
 * changed since account creation, falling back to User.createdAt
 * otherwise (see AdminUserServiceImpl#getCredential) - mirrors what the
 * Keycloak reference screen's "Created at" column shows for a Password
 * credential.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserCredentialResponse {
    private String type;
    private LocalDateTime createdAt;
}

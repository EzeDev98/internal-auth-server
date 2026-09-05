package com.internal.auth.testsupport.builder;

import com.internal.auth.feature.client.model.ClientApplication;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Fluent test-data builder for ClientApplication (a tenant). Defaults to a
 * confidential client_credentials client with no secret set - call
 * withClientSecretHash(...) with a real BCrypt hash (see
 * ClientApplication's class javadoc: PasswordEncoder, not TokenHasher) for
 * tests that authenticate as this client over HTTP Basic.
 */
public class ClientApplicationTestDataBuilder {

    private static final AtomicLong COUNTER = new AtomicLong();

    private String clientId;
    private String clientSecretHash = null;
    private String name = "Test Client Application";
    private String description = "Created by ClientApplicationTestDataBuilder";
    private Set<String> redirectUris = new LinkedHashSet<>();
    private Set<String> scopes = new LinkedHashSet<>(Set.of("openid"));
    private Set<String> grantTypes = new LinkedHashSet<>(Set.of("client_credentials"));
    private boolean enabled = true;

    private ClientApplicationTestDataBuilder() {
        this.clientId = "test-client-" + COUNTER.incrementAndGet();
    }

    public static ClientApplicationTestDataBuilder aClientApplication() {
        return new ClientApplicationTestDataBuilder();
    }

    public ClientApplicationTestDataBuilder withClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public ClientApplicationTestDataBuilder withClientSecretHash(String bcryptHash) {
        this.clientSecretHash = bcryptHash;
        return this;
    }

    public ClientApplicationTestDataBuilder withName(String name) {
        this.name = name;
        return this;
    }

    public ClientApplicationTestDataBuilder withScopes(Set<String> scopes) {
        this.scopes = new LinkedHashSet<>(scopes);
        return this;
    }

    public ClientApplicationTestDataBuilder withGrantTypes(Set<String> grantTypes) {
        this.grantTypes = new LinkedHashSet<>(grantTypes);
        return this;
    }

    public ClientApplicationTestDataBuilder withRedirectUris(Set<String> redirectUris) {
        this.redirectUris = new LinkedHashSet<>(redirectUris);
        return this;
    }

    public ClientApplicationTestDataBuilder withEnabled(boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    public ClientApplication build() {
        ClientApplication clientApplication = new ClientApplication();
        clientApplication.setClientId(clientId);
        clientApplication.setClientSecretHash(clientSecretHash);
        clientApplication.setName(name);
        clientApplication.setDescription(description);
        clientApplication.setRedirectUris(redirectUris);
        clientApplication.setScopes(scopes);
        clientApplication.setGrantTypes(grantTypes);
        clientApplication.setEnabled(enabled);
        return clientApplication;
    }
}

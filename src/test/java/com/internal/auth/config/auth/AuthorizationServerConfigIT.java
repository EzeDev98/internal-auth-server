package com.internal.auth.config.auth;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.repository.ClientApplicationRepository;
import com.internal.auth.feature.signingkey.service.SigningKeyService;
import com.internal.auth.testsupport.IntegrationTestBase;
import com.internal.auth.testsupport.TestTokenMinter;
import com.internal.auth.testsupport.builder.ClientApplicationTestDataBuilder;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Verifies the discovery documents and JWKS endpoint. */
class AuthorizationServerConfigIT extends IntegrationTestBase {

    @Autowired
    private ClientApplicationRepository clientApplicationRepository;
    @Autowired
    private TestTokenMinter testTokenMinter;
    @Autowired
    private SigningKeyService signingKeyService;

    @Value("${app.self-issuer-uri}")
    private String selfIssuerUri;

    @Test
    void oidcDiscoveryDocument_respondsWithThisAppAsIssuer() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value(selfIssuerUri))
                .andExpect(jsonPath("$.jwks_uri").value(selfIssuerUri + "/oauth2/jwks"))
                .andExpect(jsonPath("$.token_endpoint").exists());
    }

    @Test
    void oauth2AuthorizationServerDiscoveryDocument_respondsWithThisAppAsIssuer() throws Exception {
        mockMvc.perform(get("/.well-known/oauth-authorization-server"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value(selfIssuerUri))
                .andExpect(jsonPath("$.jwks_uri").value(selfIssuerUri + "/oauth2/jwks"));
    }

    @Test
    void jwksEndpoint_servesTheCurrentSigningKeysKid() throws Exception {
        String currentKid = signingKeyService.getCurrentKid();

        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys[?(@.kid == '" + currentKid + "')]").exists());
    }

    @Test
    void selfIssuedAccessToken_verifiesAgainstThePublicKeyServedAtJwks() throws Exception {
        ClientApplication client = clientApplicationRepository.save(
                ClientApplicationTestDataBuilder.aClientApplication().build());
        String accessToken = testTokenMinter.mintAccessToken(client.getId(), "some-user");

        MvcResult jwksResult = mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andReturn();
        JWKSet servedKeys = JWKSet.parse(jwksResult.getResponse().getContentAsString());

        SignedJWT signedJwt = SignedJWT.parse(accessToken);
        String kid = signedJwt.getHeader().getKeyID();
        RSAKey matchingKey = (RSAKey) servedKeys.getKeyByKeyId(kid);
        assertThat(matchingKey)
                .as("token's kid '%s' must match a key actually served at /oauth2/jwks", kid)
                .isNotNull();

        boolean signatureValid = signedJwt.verify(new RSASSAVerifier(matchingKey.toRSAPublicKey()));
        assertThat(signatureValid).as("signature must verify against the served public key").isTrue();
        assertThat(signedJwt.getJWTClaimsSet().getIssuer()).isEqualTo(selfIssuerUri);
    }
}

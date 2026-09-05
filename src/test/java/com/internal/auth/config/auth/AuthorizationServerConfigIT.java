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

/**
 * Step 11B. Confirms the two discovery documents and the JWKS endpoint
 * AuthorizationServerConfig's javadoc describes actually respond - both
 * were "not yet confirmed" / added by correction there (OIDC discovery,
 * Step 12C) rather than proven by a test - and, more importantly, that a
 * token this app mints for itself genuinely verifies against the public
 * key it serves at that JWKS endpoint. That last part is deliberately not
 * done via WebSecurityConfig#jwtDecoder (this app verifying its own token
 * with its own in-process decoder would only prove the two beans agree
 * with each other, not that a real external resource-server client could
 * do the same against the published key) - it re-parses the raw
 * /oauth2/jwks response with Nimbus directly, the same way an external
 * verifier would.
 *
 * No bearer token is sent for the discovery/JWKS requests themselves and
 * none is required: this app's own AS filter chain
 * (AuthorizationServerConfig#authorizationServerSecurityFilterChain) ends
 * in anyRequest().authenticated(), which Spring Security's default
 * AnonymousAuthenticationFilter satisfies for an anonymous caller too -
 * only fullyAuthenticated() would reject anonymous access, and this app
 * does not use that here.
 */
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

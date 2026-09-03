package com.internal.auth.config.auth;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Step 12A/12B - stands up Spring Authorization Server itself.
 *
 * <p><b>Correction (this class previously got this wrong):</b> an earlier
 * version of this class used {@code @Import(OAuth2AuthorizationServerConfiguration.class)}
 * and claimed in this javadoc that the filter chain bean it pulls in was
 * "matched only against the authorization server's own endpoints." That
 * was wrong. Disassembling the actual bytecode
 * ({@code javap -v OAuth2AuthorizationServerConfiguration.class}) shows its
 * {@code authorizationServerSecurityFilterChain} bean never calls
 * {@code .securityMatcher(...)} at all - it matches any request, exactly
 * like WebSecurityConfig's own unscoped chain does. With both beans in the
 * context, Spring Security can't tell which chain should handle a given
 * request and refuses to start
 * ({@code UnreachableFilterChainException}). That was a careless mistake:
 * scoping a filter chain is the entire point of having more than one, and
 * this class asserted it was scoped without actually checking the bytecode
 * for the one line that would have proven it.
 *
 * <p>The fix below builds the chain by hand instead of importing Spring's
 * pre-packaged one, using {@code OAuth2AuthorizationServerConfigurer}
 * directly (ground-truthed via {@code javap -p} to have a plain public
 * no-arg constructor and a public {@code getEndpointsMatcher()} instance
 * method - no static factory). {@code securityMatcher(...)} restricts this
 * bean to only the authorization server's own endpoints
 * ({@code /oauth2/*}, {@code /.well-known/*}), so WebSecurityConfig's own
 * chain remains the catch-all for everything else, and the two no longer
 * collide. {@code @Order(1)} gives this chain precedence over
 * WebSecurityConfig's (which has no explicit order, i.e. lowest priority),
 * matching the ordering Spring's own pre-packaged bean used
 * ({@code Integer.MIN_VALUE}) without needing that exact value - just
 * needs to run before the unscoped catch-all chain is evaluated. The
 * imported class also wired /oauth2/jwks automatically off the JWKSource
 * bean below; that part carries over unchanged since it's
 * {@code OAuth2AuthorizationServerConfigurer} doing that wiring either way,
 * not the {@code @Import}.
 *
 * <p>The RegisteredClientRepository this pulls in is
 * ClientApplicationRegisteredClientRepository (a plain {@code @Component},
 * picked up automatically as the one bean of that type in the context).
 *
 * <p><b>Signing key (Step 12B):</b> loaded from
 * app.authorization-server.signing-key-pem, a Base64-encoded PKCS#8 PEM
 * RSA private key (generate one with
 * {@code openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048},
 * then Base64-encode the whole PEM file onto one line - env vars don't
 * tolerate embedded newlines well). The public key and a stable key ID
 * (a SHA-256 hash of the public key itself, not a random UUID) are derived
 * from it, so the same env var value always produces the same JWK. If the
 * property is blank, this falls back to a fresh in-memory key generated on
 * the spot (Step 12A's original behavior) with a warning logged - kept as
 * a deliberate local-dev convenience rather than failing the boot outright
 * like app.token-issuer-uri does, since nothing validates self-issued
 * tokens yet (Step 12D). Revisit this fallback once that cutover happens
 * or before any real deployment - Step 14E ("real secret management") is
 * the natural home for tightening it further.
 *
 * <p><b>Issuer (app.self-issuer-uri):</b> deliberately a new, separate
 * property from app.token-issuer-uri. That existing property is this app's
 * resource-server config - the issuer it validates *incoming* bearer
 * tokens against (Keycloak, today). app.self-issuer-uri is the opposite
 * direction: the issuer this app stamps into tokens *it* mints. They must
 * stay independently configurable since they point at two different
 * systems until Step 12D's cutover makes them the same one. Defaults to
 * the same value as the existing base-url property (this server's own
 * base URL), which is exactly what an OAuth2 issuer identifier is.
 *
 * <p>Not yet confirmed (worth checking once this boots): whether
 * {@code Customizer.withDefaults()} here also enables the OIDC discovery
 * endpoint (/.well-known/openid-configuration) or only the plain OAuth2
 * one (/.well-known/oauth-authorization-server) - neither the old imported
 * class nor this hand-built configurer call {@code .oidc(...)} explicitly.
 * If OIDC discovery turns out to be off, enabling it is a small follow-up
 * for Step 12C, not a blocker here.
 *
 * <p><b>Step 12C update:</b> {@code .oidc(Customizer.withDefaults())} is
 * now explicitly enabled above, confirmed via {@code javap -p -c} on
 * {@code OAuth2AuthorizationServerConfigurer.class} to be safe to call
 * before {@code .securityMatcher(...)} despite appearing first in this
 * method: {@code getEndpointsMatcher()} returns a lazily-evaluated
 * {@code RequestMatcher} that reads an internal field populated later by
 * {@code init(HttpSecurity)} (itself run during {@code http.build()}, well
 * after {@code .oidc(...)} has already registered {@code OidcConfigurer}
 * into this configurer's internal map) - so call order here doesn't matter,
 * only that {@code .oidc(...)} runs before an actual request is served.
 * This makes /.well-known/openid-configuration live in addition to the
 * existing /.well-known/oauth-authorization-server. One nuance the same
 * bytecode surfaced: enabling {@code .oidc(...)} also makes this
 * configurer call {@code http.oauth2ResourceServer(...)} on this chain (to
 * protect the OIDC /userinfo endpoint), which will pick up whatever single
 * {@code JwtDecoder} bean exists in the context - today that's
 * WebSecurityConfig's decoder pointed at app.token-issuer-uri (Keycloak),
 * not a decoder for this app's own self-issued tokens. Not a boot blocker
 * and doesn't affect the discovery document itself, but /userinfo would
 * currently validate against the wrong issuer - that's Step 12D's territory
 * ("give tokenIssuerUrl a real value and update the JWT decoder bean"), not
 * fixed here.
 */
@Configuration
public class AuthorizationServerConfig {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationServerConfig.class);

    @Value("${app.self-issuer-uri}")
    private String selfIssuerUri;

    @Value("${app.authorization-server.signing-key-pem}")
    private String signingKeyPemBase64;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, authorizationServer -> authorizationServer.oidc(Customizer.withDefaults()))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return http.build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = loadOrGenerateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(computeKeyId(publicKey))
                .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(selfIssuerUri)
                .build();
    }

    /**
     * Step 12F. Declared explicitly rather than left to whatever
     * OAuth2AuthorizationServerConfigurer defaults to internally when no
     * bean of this type exists (client_credentials worked fine on that
     * implicit default through Step 12D, but that default isn't visible
     * outside the /oauth2/* filter chain - and LoginServiceImpl needs to
     * save an OAuth2Authorization record from a plain @Service, not from
     * inside that filter chain, since it mints a token directly on local
     * login success rather than routing through /oauth2/token - see that
     * class's javadoc). Declaring this bean makes the authorization server
     * itself use this exact instance too (OAuth2ConfigurerUtils checks the
     * application context for a bean of this type before falling back to
     * building its own), so client_credentials and local-login tokens now
     * share one authorization record store instead of two invisible ones.
     * Plain in-memory for now, same tradeoff as the ephemeral signing-key
     * fallback above - revisit alongside real secret/session persistence
     * (Step 14E) before any real deployment.
     */
    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    /**
     * Step 12F. Declared explicitly for the same reason as
     * authorizationService() above - so both the /oauth2/token endpoint and
     * LoginServiceImpl's direct in-process minting share the exact same
     * token generator, which is what makes jwtTokenCustomizer() below apply
     * uniformly to every self-issued token instead of only the ones minted
     * through the filter chain. Hand-assembled (JwtGenerator +
     * OAuth2AccessTokenGenerator, no refresh token generator - nothing
     * requests refresh tokens yet) instead of relying on
     * OAuth2AuthorizationServerConfigurer's own default composition, since
     * that default isn't a retrievable bean either.
     */
    @Bean
    public OAuth2TokenGenerator<OAuth2Token> tokenGenerator(
            JWKSource<SecurityContext> jwkSource,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer) {
        NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtTokenCustomizer);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator);
    }

    /**
     * Step 12F - stamps a "roles" claim onto every self-issued access token
     * from whatever GrantedAuthority collection is on the token's principal
     * (see SelfIssuedJwtRolesConverter's javadoc for why "roles" is this
     * app's own flat claim shape, replacing Keycloak's three-claim split).
     * For client_credentials tokens the principal is the authenticated
     * client, which carries no authorities today, so this correctly adds
     * no "roles" claim there - unchanged from Step 12E's ground truth. For
     * LoginServiceImpl's directly-minted tokens, the principal is a
     * UsernamePasswordAuthenticationToken built from that user's
     * UserRole/Role rows, so this is what actually populates "roles" for
     * the first time.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Collection<? extends GrantedAuthority> authorities = context.getPrincipal().getAuthorities();
                if (authorities != null && !authorities.isEmpty()) {
                    Set<String> roles = authorities.stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toCollection(LinkedHashSet::new));
                    context.getClaims().claim("roles", roles);
                }
            }
        };
    }

    private KeyPair loadOrGenerateRsaKey() {
        if (signingKeyPemBase64 == null || signingKeyPemBase64.isBlank()) {
            log.warn("app.authorization-server.signing-key-pem is not set - generating a throwaway RSA key for this boot only. "
                    + "Every token this server has minted becomes invalid the instant it restarts. Set AUTH_SIGNING_KEY_PEM "
                    + "for a persistent key (see this class's javadoc for how to generate one).");
            return generateEphemeralRsaKey();
        }
        return decodePemRsaKey(signingKeyPemBase64);
    }

    private KeyPair decodePemRsaKey(String base64EncodedPem) {
        String pem;
        try {
            pem = new String(Base64.getDecoder().decode(base64EncodedPem), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("app.authorization-server.signing-key-pem is not valid Base64", e);
        }

        String strippedBase64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] der;
        try {
            der = Base64.getDecoder().decode(strippedBase64);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("app.authorization-server.signing-key-pem did not decode to a valid PEM body", e);
        }

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(der));
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent());
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            return new KeyPair(publicKey, privateKey);
        } catch (GeneralSecurityException | ClassCastException e) {
            throw new IllegalStateException(
                    "app.authorization-server.signing-key-pem must be a PKCS#8-encoded RSA private key "
                            + "(e.g. from `openssl genpkey -algorithm RSA`)", e);
        }
    }

    private static KeyPair generateEphemeralRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Failed to generate a fallback ephemeral signing key", ex);
        }
    }

    /**
     * A stable key ID derived from the key itself (SHA-256 of the public
     * key's encoded form), not a random UUID - so the same signing key
     * always produces the same "kid", instead of a new one every restart
     * even when the key itself didn't change.
     */
    private static String computeKeyId(RSAPublicKey publicKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(publicKey.getEncoded());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed present on every JVM - unreachable in practice.
            return UUID.randomUUID().toString();
        }
    }
}

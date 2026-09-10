package com.internal.auth.config.auth;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.feature.signingkey.service.SigningKeyService;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
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
 * <p><b>Signing key (Step 12B, superseded by Step 14D):</b> key material
 * now lives entirely in SigningKeyService, backed by the signing_key table
 * (V16) instead of a single static env var. On first boot with an empty
 * table, it seeds one row from app.authorization-server.signing-key-pem if
 * set (same Base64-PEM format as before, so an existing deployment's key
 * carries over and doesn't invalidate outstanding tokens on upgrade), or
 * generates and persists a brand new one if that property is blank - no
 * more "regenerates every restart" fallback; once a key exists in the
 * table it survives restarts. Rotation (a new admin-only endpoint,
 * SigningKeyController) generates a new key, makes it current for signing,
 * and keeps the previous key valid for verification for
 * AppConstant.SIGNING_KEY_GRACE_PERIOD_DAYS before retiring it. See
 * SigningKeyServiceImpl's javadoc for the full lifecycle.
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

    @Value("${app.self-issuer-uri}")
    private String selfIssuerUri;

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

    /**
     * Step 14D: no longer builds a key itself - SigningKeyService owns all
     * key material (generation, PEM encode/decode, persistence, rotation).
     * This bean is a thin adapter: every JWKSource.get(...) call reads
     * whatever SigningKeyService's cache currently holds, so a rotation
     * takes effect for both this JWKS-endpoint-facing bean and the
     * tokenGenerator() bean below (they share this exact instance) without
     * either bean needing to be rebuilt or the app restarted.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource(SigningKeyService signingKeyService) {
        return (jwkSelector, securityContext) -> jwkSelector.select(signingKeyService.getJwkSet());
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
     *
     * <p>Step 3 (production-readiness fix): was
     * InMemoryOAuth2AuthorizationService - every minted token's
     * authorization record lived only in this one JVM's heap, wiped on
     * restart and not shared across instances/behind a load balancer. Now
     * JdbcOAuth2AuthorizationService, backed by the oauth2_authorization
     * table (V21 migration in prod; dev applies the equivalent table via
     * spring.sql.init.* - see application-dev.properties). The custom
     * ObjectMapper registration below is required, not optional - the
     * default row mapper needs SecurityJackson2Modules (core Spring
     * Security types) and OAuth2AuthorizationServerJackson2Module
     * (this module's own types, including custom AuthorizationGrantType
     * values like LoginServiceImpl's "local_login") registered before it
     * can (de)serialize what's stored in the attributes/token-metadata
     * columns - without them this compiles fine but throws at runtime the
     * first time a real authorization round-trips through the database.
     */
    /**
     * client_application_id is baked into the access-token claims as a boxed
     * Long in jwtTokenCustomizer() below, and that same claims map
     * round-trips through this bean's ObjectMapper whenever an authorization
     * row is written and read back. java.lang.Long isn't on
     * SecurityJackson2Modules' allowlist, so any findByToken()/findById()
     * call against a row containing that claim throws "The class with
     * java.lang.Long ... is not in the allowlist" - which is exactly the 500
     * LogoutServiceImpl.logout() was surfacing. This mixin tells Jackson to
     * (de)serialize Long as a plain number instead of routing it through the
     * allowlist-checked polymorphic type resolver; it must be applied to
     * both the row mapper (reads) and the parameters mapper (writes) below
     * so the two stay symmetric.
     */
    @JsonTypeInfo(use = JsonTypeInfo.Id.NONE)
    private static class LongMixin {
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        JdbcOAuth2AuthorizationService authorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);

        ObjectMapper objectMapper = new ObjectMapper();
        ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        objectMapper.registerModules(securityModules);
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        objectMapper.addMixIn(Long.class, LongMixin.class);

        JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper rowMapper = new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(registeredClientRepository);
        rowMapper.setObjectMapper(objectMapper);
        authorizationService.setAuthorizationRowMapper(rowMapper);

        JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper parametersMapper = new JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper();
        parametersMapper.setObjectMapper(objectMapper);
        authorizationService.setAuthorizationParametersMapper(parametersMapper);

        return authorizationService;
    }

    /**
     * Step 12F. Declared explicitly for the same reason as
     * authorizationService() above - so both the /oauth2/token endpoint and
     * LoginServiceImpl's direct in-process minting share the exact same
     * token generator, which is what makes jwtTokenCustomizer() below apply
     * uniformly to every self-issued token instead of only the ones minted
     * through the filter chain. Hand-assembled (JwtGenerator +
     * OAuth2AccessTokenGenerator + OAuth2RefreshTokenGenerator) instead of
     * relying on OAuth2AuthorizationServerConfigurer's own default
     * composition, since that default isn't a retrievable bean either.
     *
     * Step 15A addition: OAuth2RefreshTokenGenerator added to the
     * delegation chain so refresh tokens can now be minted alongside
     * access tokens (LoginServiceImpl.mintAccessToken persists both on the
     * same OAuth2Authorization record). DelegatingOAuth2TokenGenerator
     * dispatches to whichever delegate's supports() matches the requested
     * OAuth2TokenType, so adding this generator here doesn't change
     * behavior for any caller that only ever asks for an access token
     * (client_credentials still gets exactly what it got before) - it only
     * enables callers that explicitly request a REFRESH_TOKEN-typed token.
     */
    @Bean
    public OAuth2TokenGenerator<OAuth2Token> tokenGenerator(JWKSource<SecurityContext> jwkSource, OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer) {
        NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtTokenCustomizer);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
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
     *
     * Step 14D addition: also stamps the JWS header's "kid" to whichever
     * key SigningKeyService currently considers current, on every token
     * type (not just access tokens) - not optional once jwkSource() can
     * hold more than one same-algorithm key. NimbusJwtEncoder throws
     * JwtEncodingException on an ambiguous multi-key match instead of
     * picking one arbitrarily (confirmed against NimbusJwtEncoder's
     * selectJwk() source, tag 7.1.1), so without this the moment a second
     * key exists in the JWKSet every token mint would start failing.
     *
     * This-patch addition: also stamps "client_application_id" onto every
     * access token, read off the principal's details rather than a new
     * context attribute - LoginServiceImpl#mintAccessToken stashes it
     * there via Authentication#setDetails before building the token
     * context, the same extension point Spring Security's own
     * WebAuthenticationDetails uses, chosen specifically because
     * context.getPrincipal() is already proven reachable here (the roles
     * claim above already reads authorities off this exact object). Fixes
     * MfaAdminServiceImpl's previously-unscoped username lookup for the
     * self-service MFA path, which - unlike the admin path - has no
     * admin-supplied clientId to resolve it from instead. client_credentials
     * tokens never go through mintAccessToken, so their principal's
     * details is unset and this correctly adds no claim there.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(
            SigningKeyService signingKeyService,
            com.internal.auth.feature.identity.repository.UserRepository userRepository) {
        return context -> {
            context.getJwsHeader().keyId(signingKeyService.getCurrentKid());
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Collection<? extends GrantedAuthority> authorities = context.getPrincipal().getAuthorities();
                if (authorities != null && !authorities.isEmpty()) {
                    Set<String> roles = authorities.stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toCollection(LinkedHashSet::new));
                    context.getClaims().claim("roles", roles);
                }

                userRepository.findByInternalAuthUserId(context.getPrincipal().getName())
                        .ifPresent(user -> {
                            context.getClaims().claim("client_application_id", user.getClientApplicationId());
                            context.getClaims().claim("username", user.getUsername());
                            if (user.getEmail() != null) {
                                context.getClaims().claim("email", user.getEmail());
                            }
                            if (user.getPhoneNumber() != null) {
                                context.getClaims().claim("phone_number", user.getPhoneNumber());
                            }
                        });
            }
        };
    }

}
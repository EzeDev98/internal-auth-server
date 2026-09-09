package com.internal.auth.config.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

    /**
     * API-contract review (step 1): single source of truth for the API
     * base path, shared with every controller's own "${app.title}"
     * @RequestMapping. Used below to build the permitAll() matcher paths
     * instead of hardcoded "/api/v1/..." literals, so a controller's
     * mapping and its security rule can never drift apart.
     */
    @Value("${app.title}")
    private String appTitle;


    // Step 12E: swapped from KeycloakJwtRolesConverter to the equivalent for
    // this app's own self-issued claims shape - see SelfIssuedJwtRolesConverter's
    // javadoc for the claim-shape rationale and current ground-truth status
    // (correct but inert until Step 12F adds a token customizer that
    // populates the "roles" claim it reads).
    private final SelfIssuedJwtRolesConverter jwtAuthenticationConverter;

    private final CustomAccessDenied customAccessDenied;

    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    private final JwtSessionTrackingFilter jwtSessionTrackingFilter;

    /**
     * OIDC issuer this resource server validates bearer tokens against.
     * Step 12D: defaults to this app's own authorization server
     * (app.self-issuer-uri) rather than Keycloak - see
     * application.properties' app.token-issuer-uri comment for the full
     * rationale, and jwtDecoder()'s javadoc below for why it's built from
     * the JWKS URI directly rather than via issuer-location discovery.
     */
    @Value("${app.token-issuer-uri}")
    private String tokenIssuerUrl;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(headers -> headers
                        .addHeaderWriter(new StaticHeadersWriter("X-Robots-Tag", "noindex, nofollow")))
                .authorizeHttpRequests(authorize -> authorize

                        // Allow preflight CORS requests
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // Allow public endpoints
                        .requestMatchers("/public/**").permitAll()

                        // Step 14B - actuator now runs on a separate port (management.server.port,
                        // see application.properties), but that alone does NOT exempt it from this
                        // filter chain: a custom SecurityFilterChain bean (this one) makes Spring
                        // Boot's own actuator-security auto-configuration back off entirely, and
                        // this app's security applies across every connector/port it listens on,
                        // not just the main one - confirmed the hard way (both ports returned this
                        // app's own 401 JSON until this matcher was added). EndpointRequest matches
                        // actuator's actual configured paths regardless of base-path/port, which is
                        // more robust than hardcoding "/actuator/**" as a literal string.
                        .requestMatchers(EndpointRequest.toAnyEndpoint()).permitAll()

                        // Allow robots.txt for crawlers
                        .requestMatchers("/robots.txt").permitAll()

                        // Allow Swagger/OpenAPI docs
                        .requestMatchers(
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/swagger-resources/**",
                                "/configuration/**",
                                "/webjars/**",
                                "/api-docs/**"
                        ).permitAll()

                        // Block malicious scanner probes
                        .requestMatchers(maliciousProbesMatcher()).denyAll()

                        // POST endpoints accessible without a JWT (there is, by definition, no
                        // bearer token to present yet at this point in the request for most of
                        // these - they're how a caller gets authenticated in the first place).
                        // History: "/api/v1/user/login" and "/api/v1/user/refresh-token" used to
                        // sit here for the old Keycloak password-grant flow; both were retired
                        // when login moved to Keycloak's hosted page (see Stage 1 assessment).
                        // "/api/v1/auth/login" and "/api/v1/auth/login/verify-otp" are NOT a
                        // revival of that old endpoint - they're Step 11A/11E's new
                        // local-credential login with optional OTP step-up (LoginController),
                        // built once this app started owning its own User table (Stage 2)
                        // instead of delegating identity to Keycloak.
                        // "/api/v1/kyc/response" was removed here (Stage 1 punch-list item 8):
                        // confirmed wallet/KYC-domain leftover with no matching controller and no
                        // relation to Internal Auth's scope.
                        // "/api/v1/auth/register", "/api/v1/auth/activate" and
                        // "/api/v1/auth/resend-activation" are now implemented (RegistrationController,
                        // EmailVerificationController - Steps 10A/10C), not pre-wired stubs anymore.
                        // "/api/v1/auth/verify-phone" and "/api/v1/auth/resend-phone-verification"
                        // (self-service phone verification, PhoneVerificationController) fix the
                        // previously-permanent phone-only-account login gate - no self-service flow
                        // existed anywhere in this app to ever set phoneVerified=true, and a
                        // phone-only user hitting that gate by definition has no bearer token yet.
                        // "/api/v1/password-reset/request", "/verify-otp" and "/complete" were
                        // previously unreachable here: PasswordResetController used to map under
                        // "${app.title}/password-reset" (a property, not a literal), which fell
                        // through to anyReguest().authenticated() with no matching permitAll rule -
                        // the same trap RegistrationController's own Javadoc warns about, and it
                        // made password reset uncallable by the locked-out, token-less user it's
                        // for. PasswordResetController's mapping is now the literal
                        // "/api/v1/password-reset", matching every other pre-auth controller here,
                        // so this list can't silently drift from the controller again.
                        // "/api/v1/admin/register" and "/api/v1/otp/**" remain pre-wiring for
                        // not-yet-built work - confirmed with the project owner (Stage 1).
                        .requestMatchers(HttpMethod.POST,
                                appTitle + "/auth/register",
                                appTitle + "/auth/login",
                                appTitle + "/auth/login/verify-otp",
                                appTitle + "/auth/refresh-token",
                                appTitle + "/auth/activate",
                                appTitle + "/auth/resend-activation",
                                appTitle + "/auth/verify-phone",
                                appTitle + "/auth/resend-phone-verification",
                                appTitle + "/password-reset/request",
                                appTitle + "/password-reset/verify-otp",
                                appTitle + "/password-reset/complete",
                                appTitle + "/admin/register",
                                appTitle + "/admin/login",
                                appTitle + "/admin/login/verify-otp",
                                appTitle + "/otp/**"
                        ).permitAll()

                        .requestMatchers(HttpMethod.GET, appTitle + "/auth/activate").permitAll()

                        // OIDC back-channel logout - called server-to-server by Keycloak, not by a
                        // logged-in user, so there's no bearer token to check here. It authenticates
                        // itself via the signed logout_token validated in BackchannelLogoutService.
                        .requestMatchers(HttpMethod.POST, appTitle + "/logout/backchannel").permitAll()

                        .anyRequest().authenticated())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                        .accessDeniedHandler(customAccessDenied))
                // Runs after JWT validation sets the Authentication, so it can read the
                // token's sid claim and backfill UserSession tracking (see class javadoc).
                .addFilterAfter(jwtSessionTrackingFilter, BearerTokenAuthenticationFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }

    /**
     * Matches requests whose URI ends with a known malicious file extension.
     * Uses a plain string check to avoid Spring 6 PathPatternParser restrictions
     * (which disallow any characters after ** in a pattern).
     */
    private RequestMatcher maliciousProbesMatcher() {
        List<String> blockedExtensions = List.of(
                ".php", ".asp", ".aspx", ".env", ".cgi", ".sh", ".bat"
        );
        return request -> {
            String path = request.getRequestURI().toLowerCase();
            return blockedExtensions.stream().anyMatch(path::endsWith);
        };
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOriginPatterns(List.of(
                "http://localhost:*"
        ));

        configuration.setAllowedMethods(List.of(
                "GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"
        ));

        configuration.setAllowedHeaders(List.of("*"));

        configuration.setExposedHeaders(List.of(
                "Content-Disposition",
                "X-Total-Count"
        ));

        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * Step 12D history worth keeping: this was originally
     * {@code JwtDecoders.fromIssuerLocation(tokenIssuerUrl)}, then briefly
     * {@code @Lazy}-annotated in an attempt to defer that call until after
     * boot. Neither worked once tokenIssuerUrl started pointing at this
     * app's own issuer. {@code fromIssuerLocation(...)} does an eager HTTP
     * GET to {issuer}/.well-known/openid-configuration inside its own
     * {@code .build()} - unavoidable no matter when {@code .build()} runs.
     * {@code @Lazy} on this bean method didn't help either: it only stops
     * Spring's own automatic singleton pre-instantiation from creating the
     * bean eagerly, but
     * {@code OAuth2ResourceServerConfigurer.JwtConfigurer.getJwtDecoder()}
     * calls {@code applicationContext.getBean(JwtDecoder.class)} directly,
     * which always forces real construction immediately regardless of
     * {@code @Lazy} on the bean definition - confirmed by reproducing the
     * exact same ConnectException with @Lazy in place.
     *
     * <p>The actual fix: build the decoder from the JWKS URI directly
     * ({@code NimbusJwtDecoder.withJwkSetUri(...)}, confirmed via
     * {@code javap} to return a plain {@code NimbusJwtDecoder} with no
     * network I/O in {@code .build()} itself) instead of via issuer-
     * location discovery. The underlying JWKSource fetches keys lazily on
     * the first token it actually needs to verify, by which point the
     * server is definitely up. Since {@code withJwkSetUri(...)} doesn't
     * set up issuer validation the way {@code fromIssuerLocation(...)}
     * does automatically, {@code JwtValidators.createDefaultWithIssuer(...)}
     * adds that back explicitly so a token minted by a different issuer is
     * still rejected.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(tokenIssuerUrl + "/oauth2/jwks").build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(tokenIssuerUrl));
        return decoder;
    }

    @Bean
    public GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults("");
    }

    /**
     * The app-wide password hasher: BCrypt, for values that need brute-force
     * resistance and are only ever verified against an already-located row
     * (users.password, and eventually client_applications.client_secret_hash).
     * For values that instead need to be looked up directly by their hash
     * (session tokens, password-reset tokens), see TokenHasher (SHA-256) -
     * Stage 2 punch-list item 4 (credential storage policy) covers why these
     * are deliberately two different mechanisms.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
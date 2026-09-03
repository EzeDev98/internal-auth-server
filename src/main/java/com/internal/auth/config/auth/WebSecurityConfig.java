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
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
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

    private final KeycloakJwtRolesConverter jwtAuthenticationConverter;

    private final CustomAccessDenied customAccessDenied;

    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    private final JwtSessionTrackingFilter jwtSessionTrackingFilter;

    /**
     * OIDC issuer this resource server validates bearer tokens against.
     * Must be set externally (application.properties / env) to a real,
     * reachable issuer - there is no safe default. See the Stage 1
     * assessment's "Token Management" notes: today that's Keycloak; longer
     * term this becomes Internal Auth's own OIDC/JWKS endpoint (Stage 4).
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
                        // Allow actuator health endpoint for Docker health checks
                        .requestMatchers("/actuator/health").permitAll()

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
                        // "/api/v1/admin/register" and "/api/v1/otp/**" remain pre-wiring for
                        // not-yet-built work - confirmed with the project owner (Stage 1).
                        .requestMatchers(HttpMethod.POST,
                                "/api/v1/auth/register",
                                "/api/v1/auth/login",
                                "/api/v1/auth/login/verify-otp",
                                "/api/v1/auth/activate",
                                "/api/v1/auth/resend-activation",
                                "/api/v1/admin/register",
                                "/api/v1/otp/**"
                        ).permitAll()

                        .requestMatchers(HttpMethod.GET, "/api/v1/auth/activate").permitAll()

                        // OIDC back-channel logout - called server-to-server by Keycloak, not by a
                        // logged-in user, so there's no bearer token to check here. It authenticates
                        // itself via the signed logout_token validated in BackchannelLogoutService.
                        .requestMatchers(HttpMethod.POST, "/api/v1/logout/backchannel").permitAll()

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
                "https://*.thewessmarket.com",
                "https://*.thewealthmarket.com",
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

    @Bean
    public JwtDecoder jwtDecoder() {
        return JwtDecoders.fromIssuerLocation(tokenIssuerUrl);
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

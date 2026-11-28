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

import java.util.Arrays;
import java.util.List;

/** Configures the HTTP security filter chain, CORS and resource server. */
@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {
    @Value("${app.title}")
    private String appTitle;

    private final SelfIssuedJwtRolesConverter jwtAuthenticationConverter;

    private final CustomAccessDenied customAccessDenied;

    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    private final JwtSessionTrackingFilter jwtSessionTrackingFilter;

    @Value("${app.token-issuer-uri}")
    private String tokenIssuerUrl;

    @Value("${app.cors.allowed-origins}")
    private String allowedOrigins;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(headers -> headers
                        .addHeaderWriter(new StaticHeadersWriter("X-Robots-Tag", "noindex, nofollow")))
                .authorizeHttpRequests(authorize -> authorize

                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        .requestMatchers("/public/**").permitAll()

                        .requestMatchers(EndpointRequest.toAnyEndpoint()).permitAll()

                        .requestMatchers("/robots.txt").permitAll()

                        .requestMatchers(
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/swagger-resources/**",
                                "/configuration/**",
                                "/webjars/**",
                                "/api-docs/**"
                        ).permitAll()

                        .requestMatchers(maliciousProbesMatcher()).denyAll()

                        .requestMatchers(HttpMethod.POST,
                                appTitle + "/auth/register",
                                appTitle + "/auth/login",
                                appTitle + "/auth/refresh-token",
                                appTitle + "/auth/session-status",
                                appTitle + "/auth/change-password",
                                appTitle + "/auth/activate",
                                appTitle + "/auth/resend-activation",
                                appTitle + "/auth/verify-phone",
                                appTitle + "/auth/resend-phone-verification",
                                appTitle + "/password-reset/request",
                                appTitle + "/password-reset/verify-otp",
                                appTitle + "/password-reset/email/request",
                                appTitle + "/password-reset/email/verify-otp",
                                appTitle + "/password-reset/complete",
                                appTitle + "/admin/register",
                                appTitle + "/admin/login",
                                appTitle + "/admin/refresh-token",
                                appTitle + "/admin/password-reset/request",
                                appTitle + "/admin/password-reset/verify-otp",
                                appTitle + "/admin/reset/wipe-tenant",
                                appTitle + "/admin/reset/wipe-all",
                                appTitle + "/logout/backchannel",
                                appTitle + "/otp/**"
                        ).permitAll()

                        .requestMatchers(HttpMethod.GET, appTitle + "/keep-alive").permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/actuator/health").permitAll()

                        .requestMatchers(HttpMethod.GET, appTitle + "/auth/activate").permitAll()

                        .anyRequest().authenticated())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                        .accessDeniedHandler(customAccessDenied))
                .addFilterAfter(jwtSessionTrackingFilter, BearerTokenAuthenticationFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }

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

        configuration.setAllowedOriginPatterns(
                Arrays.stream(allowedOrigins.split(","))
                        .map(String::trim)
                        .filter(origin -> !origin.isEmpty())
                        .toList()
        );

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
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(tokenIssuerUrl + "/oauth2/jwks").build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(tokenIssuerUrl));
        return decoder;
    }

    @Bean
    public GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults("");
    }
}

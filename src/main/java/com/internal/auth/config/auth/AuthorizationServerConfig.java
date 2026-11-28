package com.internal.auth.config.auth;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.internal.auth.feature.identity.repository.UserRepository;
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

/** Configures Spring Authorization Server, token signing and token customisation. */
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

    @Bean
    public OAuth2TokenGenerator<OAuth2Token> tokenGenerator(JWKSource<SecurityContext> jwkSource, OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer) {
        NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtTokenCustomizer);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(SigningKeyService signingKeyService, UserRepository userRepository) {
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

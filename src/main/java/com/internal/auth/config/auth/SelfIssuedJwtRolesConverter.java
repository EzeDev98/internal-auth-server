package com.internal.auth.config.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

/** Converts role claims on self-issued JWTs into Spring Security authorities. */
@Slf4j
@Component
public class SelfIssuedJwtRolesConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        log.debug("Extracted authorities: {}", authorities);
        return new JwtAuthenticationToken(jwt, authorities);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        List<String> roles = jwt.getClaim("roles");

        if (roles == null) {
            return Collections.emptyList();
        }

        return roles.stream()
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority(role.toLowerCase(Locale.ROOT)))
                .collect(Collectors.toSet());
    }
}

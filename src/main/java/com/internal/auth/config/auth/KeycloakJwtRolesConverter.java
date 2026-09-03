package com.internal.auth.config.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@Component
public class KeycloakJwtRolesConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        log.debug("Extracted authorities: {}", authorities);
        return new JwtAuthenticationToken(jwt, authorities);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        return Stream.of(
                extractRealmRoles(jwt),
                extractResourceRoles(jwt),
                extractGroups(jwt)
        ).flatMap(Collection::stream).collect(Collectors.toSet());
    }

    /**
     * Extracts realm-level roles from the "realm_access.roles" JWT claim.
     * Roles are stored in lowercase without any prefix (e.g. "basic-access", "manage-address").
     * This matches the convention used in RolesEvaluator and WebSecurityConfig's hasRole() checks.
     * NOTE: WebSecurityConfig registers GrantedAuthorityDefaults("") to remove the default
     * "ROLE_" prefix requirement, so hasRole("basic-access") works as expected.
     */
    private Collection<GrantedAuthority> extractRealmRoles(Jwt jwt) {

        Map<String, Object> realmAccess = jwt.getClaim("realm_access");

        if (realmAccess == null || !realmAccess.containsKey("roles")) {
            return Collections.emptyList();
        }

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) realmAccess.get("roles");

        if (roles == null) return Collections.emptyList();

        Collection<GrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.toLowerCase(Locale.ROOT)))
                .collect(Collectors.toList());

        log.debug("Extracted realm roles: {}", authorities);
        return authorities;
    }

    /**
     * Extracts client/resource-level roles from "resource_access.<client>.roles".
     * Stored as "<client-name>:<role-name>" in lowercase (e.g. "my-client:manage-users").
     * The colon separator prevents collisions with realm roles of the same name.
     */
    private Collection<GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");

        if (resourceAccess == null) {
            return Collections.emptyList();
        }

        return resourceAccess.entrySet().stream()
                .filter(entry -> entry.getValue() instanceof Map)
                .flatMap(entry -> {
                    String resource = entry.getKey().toLowerCase(Locale.ROOT);

                    @SuppressWarnings("unchecked")
                    Map<String, Object> resourceData = (Map<String, Object>) entry.getValue();

                    @SuppressWarnings("unchecked")
                    List<String> roles = (List<String>) resourceData.get("roles");

                    if (roles == null) return Stream.empty();

                    return roles.stream()
                            .map(role -> new SimpleGrantedAuthority(
                                    resource + ":" + role.toLowerCase(Locale.ROOT)));
                })
                .collect(Collectors.toList());
    }

    /**
     * Extracts groups from the "groups" JWT claim.
     * Stored with a "group:" prefix in lowercase (e.g. "group:operations").
     */
    private Collection<GrantedAuthority> extractGroups(Jwt jwt) {
        List<String> groups = jwt.getClaim("groups");

        if (groups == null) {
            return Collections.emptyList();
        }

        return groups.stream()
                .map(group -> new SimpleGrantedAuthority("group:" + group.toLowerCase(Locale.ROOT)))
                .collect(Collectors.toList());
    }
}
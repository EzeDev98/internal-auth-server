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

/**
 * Step 12E - the equivalent of KeycloakJwtRolesConverter for this app's own,
 * self-issued token claims shape, now that Step 12D validates bearer tokens
 * against this app's own issuer instead of Keycloak.
 *
 * <p>KeycloakJwtRolesConverter is kept in place, not deleted, per the
 * roadmap ("a documented good template") - this class replaces it as the
 * one WebSecurityConfig actually wires in.
 *
 * <p>This app's own role model (Role/UserRole - see RolesRepository) is
 * flat: a user just has zero or more Role.roleName strings, with none of
 * Keycloak's realm/resource-client/group split (that split is why
 * KeycloakJwtRolesConverter read three separate claims:
 * realm_access.roles, resource_access.&lt;client&gt;.roles, and groups).
 * The equivalent here is a single flat "roles" claim - a JSON array of
 * role-name strings, read verbatim (lowercased defensively) to match the
 * existing Roles.HAS_ADMIN / HAS_USER / HAS_SERVICE hasRole(...) literals
 * and the GrantedAuthorityDefaults("") registered in WebSecurityConfig
 * (which removes the default "ROLE_" prefix requirement).
 *
 * <p><b>Ground truth as of Step 12E:</b> nothing in this app currently puts
 * a "roles" claim into a minted token. The only grant that works today
 * (client_credentials, exercised end-to-end in Step 12D) is
 * machine-to-machine and never carries a user identity, so there is no
 * role to stamp on regardless of claim shape. That makes this converter
 * correct but inert until Step 12F (a custom OAuth2 grant type wiring
 * LoginServiceImpl's local username/password/OTP login into real token
 * issuance) adds a token customizer that actually populates this claim for
 * user-authenticated tokens. Until then, every self-issued token this app
 * can mint legitimately resolves to zero granted authorities here - that
 * is the honest, correct behavior for a client_credentials token, not a
 * bug in this converter.
 */
@Slf4j
@Component
public class SelfIssuedJwtRolesConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        log.debug("Extracted authorities: {}", authorities);
        return new JwtAuthenticationToken(jwt, authorities);
    }

    /**
     * Extracts roles from this app's own flat "roles" claim - see the class
     * javadoc for why one flat claim replaces Keycloak's three-claim split.
     */
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

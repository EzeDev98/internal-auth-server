package com.internal.auth.config.auth;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for SelfIssuedJwtRolesConverter. */
class SelfIssuedJwtRolesConverterTest {

    private final SelfIssuedJwtRolesConverter converter = new SelfIssuedJwtRolesConverter();

    @Test
    void convert_flatRolesClaimBecomesLowercasedAuthorities() {
        Jwt jwt = jwtWithRoles(List.of("ADMIN", "basic_access"));

        var token = converter.convert(jwt);

        assertThat(token).isInstanceOf(JwtAuthenticationToken.class);
        assertThat(token.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("admin", "basic_access");
    }

    @Test
    void convert_missingRolesClaimYieldsNoAuthorities() {
        Jwt jwt = jwtWithClaims(Map.of());

        var token = converter.convert(jwt);

        assertThat(token.getAuthorities()).isEmpty();
    }

    @Test
    void convert_emptyRolesClaimYieldsNoAuthorities() {
        Jwt jwt = jwtWithRoles(List.of());

        var token = converter.convert(jwt);

        assertThat(token.getAuthorities()).isEmpty();
    }

    @Test
    void convert_duplicateRoleNamesAreNotDoubleCounted() {
        Jwt jwt = jwtWithRoles(List.of("admin", "ADMIN", "Admin"));

        var token = converter.convert(jwt);

        assertThat(token.getAuthorities()).hasSize(1);
        assertThat(token.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("admin");
    }

    private Jwt jwtWithRoles(List<String> roles) {
        return jwtWithClaims(Map.of("roles", roles));
    }

    private Jwt jwtWithClaims(Map<String, Object> extraClaims) {
        Jwt.Builder builder = Jwt.withTokenValue("test-token-value")
                .header("alg", "RS256")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .claim("sub", "test-user");
        extraClaims.forEach(builder::claim);
        return builder.build();
    }
}

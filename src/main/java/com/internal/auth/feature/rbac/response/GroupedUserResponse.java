package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class GroupedUserResponse {
    private Long userId;
    private String username;
    private String email;

    /**
     * Every group and subgroup this user belongs to across the whole
     * system (not just the group this response is for), formatted as
     * slash paths and comma-joined - e.g. "/lagos, /lagos/eti-osa,
     * /offline_pay_base_access_group" - matching Keycloak's own Members
     * tab "Membership" column. Built in DtoMapper#buildMembershipPaths.
     */
    private String membership;
}

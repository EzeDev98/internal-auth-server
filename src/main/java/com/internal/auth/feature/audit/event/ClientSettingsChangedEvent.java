package com.internal.auth.feature.audit.event;

import lombok.*;

/**
 * Published by ClientApplicationServiceImpl when an admin creates a client or
 * changes its session settings (refresh-token rotation, refresh lifetime,
 * maximum session lifetime, revoke-prior-sessions). Carries only primitives so
 * the audit module never depends on the client module. Needs a no-arg
 * constructor and setters for the JDBC event publication registry's Jackson
 * round trip, same as UserLoggedInEvent.
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode
public class ClientSettingsChangedEvent {
    private String actorUsername;
    private Long clientApplicationId;
    private String description;
}

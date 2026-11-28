package com.internal.auth.feature.audit.event;

import lombok.*;

/** Event published when a client application's session settings are created or changed. */
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

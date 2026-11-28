package com.internal.auth.feature.audit.event;

import lombok.*;

/** Event published when a user completes a login. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode
public class UserLoggedInEvent {
    private Long userId;
    private String username;
    private Long clientApplicationId;
}

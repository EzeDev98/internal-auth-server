package com.internal.auth.feature.audit.event;

import lombok.*;

/**
 * Step 14A - published directly by whichever business service completes a
 * login (see LoginServiceImpl.login()/verifyLoginOtp(), fix 3b of
 * fix3modulithboundaries.md), consumed by AuditEventListener. Needs a
 * no-arg constructor and setters (not just {@code @AllArgsConstructor}) so
 * Jackson - which the JDBC event publication registry uses to serialize
 * this into event_publication.serialized_event - can deserialize it back
 * on replay without needing a separate Jackson module.
 *
 * {@code @EqualsAndHashCode} is for test convenience (asserting a captured/
 * verified event by value) - this class carries no identity of its own
 * beyond its three fields.
 */
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

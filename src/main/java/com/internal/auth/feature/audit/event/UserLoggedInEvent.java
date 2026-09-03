package com.internal.auth.feature.audit.event;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Step 14A - published by AuditServiceImpl.recordUserLoggedIn(), consumed
 * by AuditEventListener. Needs a no-arg constructor and setters (not just
 * {@code @AllArgsConstructor}) so Jackson - which the JDBC event
 * publication registry uses to serialize this into
 * event_publication.serialized_event - can deserialize it back on replay
 * without needing a separate Jackson module.
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserLoggedInEvent {
    private Long userId;
    private String username;
    private Long clientApplicationId;
}

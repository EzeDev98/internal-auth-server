package com.internal.auth.feature.session.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** Whether a user still has a live session for the calling client. */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SessionStatusResponse {
    private boolean active;
}

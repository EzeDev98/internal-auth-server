package com.internal.auth.feature.session.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** Whether the user still holds a live refresh token for the calling client. */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SessionStatusResponse {
    private boolean active;
}

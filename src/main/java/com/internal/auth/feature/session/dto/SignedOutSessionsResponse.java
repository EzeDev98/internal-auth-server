package com.internal.auth.feature.session.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Step 17h: how many of the caller's other devices DELETE /session/others signed out. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SignedOutSessionsResponse {
    private int signedOut;
}

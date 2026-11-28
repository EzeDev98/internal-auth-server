package com.internal.auth.feature.session.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Number of the caller's other sessions that were signed out. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SignedOutSessionsResponse {
    private int signedOut;
}

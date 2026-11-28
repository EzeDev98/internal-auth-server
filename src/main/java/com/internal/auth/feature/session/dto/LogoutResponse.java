package com.internal.auth.feature.session.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Result of a logout. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class LogoutResponse {
    private String message;
    private int statusCode;
}

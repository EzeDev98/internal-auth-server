package com.internal.auth.feature.admin.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for wiping all data across the connected apps. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class WipeAllRequest {
    private String confirmation;

    private Boolean includeSystemWallet;
}

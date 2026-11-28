package com.internal.auth.feature.client.dto;

import com.internal.auth.feature.client.enums.ClientType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/** List row for a client application, without secrets. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ClientApplicationSummaryResponse {
    private Long id;
    private String clientId;
    private String name;
    private ClientType type;
    private boolean enabled;
    private LocalDateTime createdAt;
}

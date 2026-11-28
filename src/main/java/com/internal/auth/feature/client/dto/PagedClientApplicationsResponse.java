package com.internal.auth.feature.client.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/** Paged list of client applications. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PagedClientApplicationsResponse {
    private List<ClientApplicationSummaryResponse> content;
    private int page;
    private int size;
    private long totalElements;
    private int totalPages;
}

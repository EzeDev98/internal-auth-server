package com.internal.auth.feature.client.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/**
 * Pagination envelope for GET ${app.title}/client-applications (Step 2B,
 * React Admin Client plan v4) - same hand-rolled shape as
 * PagedUsersResponse (Step 2A) rather than serializing Spring Data's Page
 * directly.
 */
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

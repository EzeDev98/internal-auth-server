package com.internal.auth.feature.session.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/**
 * Pagination envelope for GET ${app.title}/admin/sessions (Step 2E,
 * React Admin Client plan v4) - same hand-rolled shape as
 * PagedUsersResponse (Step 2A).
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PagedAdminSessionsResponse {
    private List<AdminSessionSummaryResponse> content;
    private int page;
    private int size;
    private long totalElements;
    private int totalPages;
}

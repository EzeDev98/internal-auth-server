package com.internal.auth.feature.session.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/** Paged list of sessions for the admin view. */
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

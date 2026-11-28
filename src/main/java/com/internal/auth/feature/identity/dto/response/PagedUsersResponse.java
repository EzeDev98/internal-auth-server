package com.internal.auth.feature.identity.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/** Paged list of users. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PagedUsersResponse {
    private List<UserSummaryResponse> content;
    private int page;
    private int size;
    private long totalElements;
    private int totalPages;
}

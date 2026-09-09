package com.internal.auth.feature.identity.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/**
 * Pagination envelope for GET ${app.title}/users (Step 2A, React Admin
 * Client plan v4) - hand-rolled the same way every other response in this
 * app is (see CreateClientApplicationResponse, RoleResponse, etc.) rather
 * than serializing Spring Data's Page directly.
 */
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

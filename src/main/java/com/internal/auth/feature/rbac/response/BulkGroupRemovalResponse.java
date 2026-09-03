package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class BulkGroupRemovalResponse {

    private int totalRequested;
    private int successfullyRemoved;
    private int notInGroup;
    private int failed;
    private List<String> removedUsers;
    private List<String> notInGroupUsers;
    private List<String> failures;
}

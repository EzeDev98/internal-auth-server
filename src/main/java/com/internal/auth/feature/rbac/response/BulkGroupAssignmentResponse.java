package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class BulkGroupAssignmentResponse {
    private int statusCode;
    private String message;
    private List<String> successfullyAdded;
    private Map<String, List<String>> details;
}
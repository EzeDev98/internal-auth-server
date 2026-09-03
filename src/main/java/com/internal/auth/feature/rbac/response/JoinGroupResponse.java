package com.internal.auth.feature.rbac.response;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class JoinGroupResponse {

    private String message;
    private int statusCode;
    private String groupName;
    private List<String> groupNames;
    private String username;

    public JoinGroupResponse(String message, int statusCode, List<String> groupNames, String username) {
        this.message = message;
        this.statusCode = statusCode;
        this.groupNames = groupNames;
        this.username = username;
    }

    public JoinGroupResponse(String message, int statusCode, String groupName, String username) {
        this.message = message;
        this.statusCode = statusCode;
        this.groupName = groupName;
        this.username = username;
    }
}

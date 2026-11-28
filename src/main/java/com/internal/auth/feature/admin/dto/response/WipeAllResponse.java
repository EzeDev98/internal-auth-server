package com.internal.auth.feature.admin.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Map;

/** Result of a full wipe across the connected apps. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class WipeAllResponse {

    private boolean completedFully;
    private List<Step> steps;

    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Step {
        private String service;
        private boolean success;
        private String message;
        private Map<String, Long> deletedCounts;
    }
}

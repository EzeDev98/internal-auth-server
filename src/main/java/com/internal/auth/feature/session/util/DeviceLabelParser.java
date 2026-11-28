package com.internal.auth.feature.session.util;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/** Builds a short device label from a User-Agent header. */
public final class DeviceLabelParser {

    public static final String UNKNOWN_DEVICE = "Unknown device";

    private static final String SEPARATOR = ", ";

    private static final List<Map.Entry<Pattern, String>> PLATFORMS = List.of(
            Map.entry(Pattern.compile("iPhone"), "iPhone"),
            Map.entry(Pattern.compile("iPad"), "iPad"),
            Map.entry(Pattern.compile("Android"), "Android"),
            Map.entry(Pattern.compile("CrOS"), "Chromebook"),
            Map.entry(Pattern.compile("Windows"), "Windows PC"),
            Map.entry(Pattern.compile("Macintosh|Mac OS X"), "Mac"),
            Map.entry(Pattern.compile("Linux"), "Linux"));

    private static final List<Map.Entry<Pattern, String>> BROWSERS = List.of(
            Map.entry(Pattern.compile("Edg(A|iOS)?/"), "Edge"),
            Map.entry(Pattern.compile("OPR/"), "Opera"),
            Map.entry(Pattern.compile("Firefox/|FxiOS"), "Firefox"),
            Map.entry(Pattern.compile("CriOS|Chrome/"), "Chrome"),
            Map.entry(Pattern.compile("Safari/"), "Safari"));

    private DeviceLabelParser() {
    }

    public static String label(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return UNKNOWN_DEVICE;
        }
        String platform = firstMatch(PLATFORMS, userAgent);
        String browser = firstMatch(BROWSERS, userAgent);
        if (platform == null && browser == null) {
            return UNKNOWN_DEVICE;
        }
        if (platform == null || browser == null) {
            return platform != null ? platform : browser;
        }
        return platform + SEPARATOR + browser;
    }

    private static String firstMatch(List<Map.Entry<Pattern, String>> candidates, String userAgent) {
        return candidates.stream()
                .filter(candidate -> candidate.getKey().matcher(userAgent).find())
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(null);
    }
}

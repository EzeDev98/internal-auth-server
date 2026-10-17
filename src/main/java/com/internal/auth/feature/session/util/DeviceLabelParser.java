package com.internal.auth.feature.session.util;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Step 17h (B-14): a short name for the device behind a User-Agent, for a "devices signed in"
 * screen: "Mac, Chrome", "iPhone, Safari", "Windows PC, Edge". A User-Agent cannot tell a MacBook
 * from an iMac, so the label never claims more than the string says. Computed once, when the
 * session is created, and stored in user_sessions.device_label.
 */
public final class DeviceLabelParser {

    public static final String UNKNOWN_DEVICE = "Unknown device";

    private static final String SEPARATOR = ", ";

    /* Order matters: an iPhone string also says "Mac OS X", an Android one also says "Linux". */
    private static final List<Map.Entry<Pattern, String>> PLATFORMS = List.of(
            Map.entry(Pattern.compile("iPhone"), "iPhone"),
            Map.entry(Pattern.compile("iPad"), "iPad"),
            Map.entry(Pattern.compile("Android"), "Android"),
            Map.entry(Pattern.compile("CrOS"), "Chromebook"),
            Map.entry(Pattern.compile("Windows"), "Windows PC"),
            Map.entry(Pattern.compile("Macintosh|Mac OS X"), "Mac"),
            Map.entry(Pattern.compile("Linux"), "Linux"));

    /* Edge and Opera also say "Chrome", and Chrome also says "Safari", so the specific ones come first. */
    private static final List<Map.Entry<Pattern, String>> BROWSERS = List.of(
            Map.entry(Pattern.compile("Edg(A|iOS)?/"), "Edge"),
            Map.entry(Pattern.compile("OPR/"), "Opera"),
            Map.entry(Pattern.compile("Firefox/|FxiOS"), "Firefox"),
            Map.entry(Pattern.compile("CriOS|Chrome/"), "Chrome"),
            Map.entry(Pattern.compile("Safari/"), "Safari"));

    private DeviceLabelParser() {
    }

    /** "Mac, Chrome"; one part when only one is known; {@link #UNKNOWN_DEVICE} when neither is. */
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

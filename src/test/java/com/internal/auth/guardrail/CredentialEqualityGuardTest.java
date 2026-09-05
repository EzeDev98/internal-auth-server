package com.internal.auth.guardrail;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Step 3C - a static, textual guard against the specific regression this
 * app's credential-storage policy exists to prevent: comparing a
 * password / OTP / client-secret hash with .equals() instead of going
 * through PasswordEncoder#matches(...) (see TokenHasher's javadoc for the
 * full rationale of what belongs behind BCrypt vs SHA-256).
 *
 * <p>This is deliberately a blunt textual scan, not a real static-analysis
 * tool - it exists to fail loudly the day someone pastes in a .equals()
 * check against one of these fields, not to catch every conceivable
 * disguised variant. {@link #ALLOWED_LINES} is the one known, reviewed
 * exception found when this test was written: comparing two plaintext
 * user-input fields (new-password vs confirm-password) for equality is not
 * a credential lookup and has nothing to do with this policy. Widen that
 * set only after checking why a new match showed up - not to silence a
 * genuine regression.
 */
class CredentialEqualityGuardTest {

    private static final Path MAIN_SOURCE_ROOT = Paths.get("src", "main", "java");

    private static final List<String> FORBIDDEN_KEYWORDS =
            List.of("password", "otphash", "clientsecrethash", "secret");

    private static final Set<String> ALLOWED_LINES = Set.of(
            "if (!confirmPassword.equals(newPassword)) {"
    );

    @Test
    void noCredentialHashIsComparedWithEquals() {
        assertThat(Files.exists(MAIN_SOURCE_ROOT))
                .as("expected to find %s from the project root - run this test with the module base "
                        + "directory as the working directory", MAIN_SOURCE_ROOT)
                .isTrue();

        List<String> violations = new ArrayList<>();

        try (Stream<Path> files = Files.walk(MAIN_SOURCE_ROOT)) {
            files.filter(path -> path.toString().endsWith(".java"))
                    .forEach(path -> scanFile(path, violations));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to walk " + MAIN_SOURCE_ROOT, e);
        }

        assertThat(violations)
                .as("found .equals() comparisons against what looks like a password/OTP/secret hash - "
                        + "use PasswordEncoder#matches(...) instead (see TokenHasher's javadoc)")
                .isEmpty();
    }

    private void scanFile(Path path, List<String> violations) {
        List<String> lines;
        try {
            lines = Files.readAllLines(path);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read " + path, e);
        }

        for (int i = 0; i < lines.size(); i++) {
            String trimmed = lines.get(i).trim();
            String lower = trimmed.toLowerCase(Locale.ROOT);

            if (!lower.contains(".equals(")) {
                continue;
            }
            if (ALLOWED_LINES.contains(trimmed)) {
                continue;
            }
            boolean suspicious = FORBIDDEN_KEYWORDS.stream().anyMatch(lower::contains);
            if (suspicious) {
                violations.add(path + ":" + (i + 1) + ": " + trimmed);
            }
        }
    }
}

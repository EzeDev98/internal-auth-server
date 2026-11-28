package com.internal.auth.feature.audit;

import com.internal.auth.feature.audit.enums.AuditAction;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/** Fails when an audit action is referenced without its own test. */
class AuditActionCoverageTest {

    private static final Path MAIN_SOURCE_ROOT = Paths.get("src", "main", "java");

    @Test
    void auditActionHasExactlyTheWiredValues() {
        assertThat(AuditAction.values())
                .as("a new AuditAction value means a new audit event is being wired - see this "
                        + "class's Javadoc before adding one without a matching test")
                .containsExactly(AuditAction.LOGIN_SUCCESS, AuditAction.CLIENT_SESSION_SETTINGS_CHANGED);
    }

    @Test
    void onlyWiredAuditActionsAreReferencedInMainSource() {
        assertThat(Files.exists(MAIN_SOURCE_ROOT))
                .as("expected to find %s from the project root - run this test with the module base "
                        + "directory as the working directory", MAIN_SOURCE_ROOT)
                .isTrue();

        List<String> violations = new ArrayList<>();

        try (Stream<Path> files = Files.walk(MAIN_SOURCE_ROOT)) {
            files.filter(path -> path.toString().endsWith(".java"))
                    .filter(path -> !path.getFileName().toString().equals("AuditAction.java"))
                    .forEach(path -> scanFile(path, violations));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to walk " + MAIN_SOURCE_ROOT, e);
        }

        assertThat(violations)
                .as("found an AuditAction reference other than LOGIN_SUCCESS - if a new action was "
                        + "just wired up (failed-login, admin-action, role-change, ...), it needs its "
                        + "own test, and this guard's expectations need updating alongside it")
                .isEmpty();
    }

    private void scanFile(Path path, List<String> violations) {
        try {
            List<String> lines = Files.readAllLines(path);
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                if (line.contains("AuditAction.") && !line.contains("AuditAction.LOGIN_SUCCESS")
                        && !line.contains("AuditAction.CLIENT_SESSION_SETTINGS_CHANGED")) {
                    violations.add(path + ":" + (i + 1) + ": " + line.trim());
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read " + path, e);
        }
    }
}

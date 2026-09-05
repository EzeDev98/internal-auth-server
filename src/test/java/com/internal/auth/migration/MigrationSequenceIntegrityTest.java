package com.internal.auth.migration;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Step 10C. A cheap, no-database static check on the migration set itself:
 * every file under db/migration must follow the plain V<n>__description.sql
 * naming this project uses throughout (no dotted sub-versions, no
 * repeatable R__ migrations), and the resulting version numbers must form
 * one contiguous run starting at 1 with no gaps and no duplicates. Flyway
 * itself would eventually surface a duplicate version as a startup failure,
 * and would silently tolerate a gap (it only cares about strict ordering,
 * not contiguity) - this test catches both mistakes at build time, before
 * either one reaches a real environment.
 */
class MigrationSequenceIntegrityTest {

    private static final Pattern VERSIONED_MIGRATION_FILENAME = Pattern.compile("^V(\\d+)__.+\\.sql$");

    @Test
    void migrationVersionsAreContiguousFromOneWithNoGapsOrDuplicates() throws IOException {
        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
        Resource[] migrations = resolver.getResources("classpath:db/migration/*.sql");
        assertThat(migrations).as("db/migration must be on the classpath").isNotEmpty();

        List<Integer> versions = new ArrayList<>();
        for (Resource migration : migrations) {
            String filename = migration.getFilename();
            Matcher matcher = VERSIONED_MIGRATION_FILENAME.matcher(filename == null ? "" : filename);
            assertThat(matcher.matches())
                    .as("%s must follow the plain V<n>__description.sql naming this project uses throughout", filename)
                    .isTrue();
            versions.add(Integer.valueOf(matcher.group(1)));
        }

        List<Integer> sortedVersions = versions.stream().sorted().toList();

        assertThat(sortedVersions)
                .as("no two migrations may share the same version number")
                .doesNotHaveDuplicates();

        List<Integer> expectedContiguousRun = IntStream.rangeClosed(1, sortedVersions.size())
                .boxed()
                .toList();

        assertThat(sortedVersions)
                .as("migration versions must run contiguously from V1 with no gaps")
                .isEqualTo(expectedContiguousRun);
    }
}

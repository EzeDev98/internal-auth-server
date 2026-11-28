package com.internal.auth.migration;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/** Verifies only the reviewed migrations contain a TRUNCATE statement. */
class MigrationTruncateInventoryTest {

    private static final Pattern TRUNCATE_STATEMENT = Pattern.compile("(?i)\\bTRUNCATE\\s+TABLE\\b");

    @Test
    void onlyTheReviewedMigrationsContainARealTruncateStatement() throws IOException {
        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
        Resource[] migrations = resolver.getResources("classpath:db/migration/*.sql");
        assertThat(migrations).as("db/migration must be on the classpath").isNotEmpty();

        List<String> migrationsContainingTruncate = new ArrayList<>();
        for (Resource migration : migrations) {
            String sql = migration.getContentAsString(StandardCharsets.UTF_8);
            if (TRUNCATE_STATEMENT.matcher(sql).find()) {
                migrationsContainingTruncate.add(migration.getFilename());
            }
        }

        assertThat(migrationsContainingTruncate).containsExactlyInAnyOrder(
                "V8__users_client_application_scoping.sql",
                "V9__otp_client_application_scoping.sql");
    }
}

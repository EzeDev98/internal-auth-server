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

/**
 * Step 10B (part 1). Flyway never re-applies an already-successful
 * migration against a populated database - that is inherent to how it
 * tracks flyway_schema_history - so "V8/V12 never run against real rows"
 * is not something a runtime test can assert about history that has
 * already happened. What this locks in instead is the actual review gate:
 * an explicit, reviewed inventory of exactly which migrations contain a
 * real (data-destroying) TRUNCATE statement. If a future migration adds an
 * undisclosed TRUNCATE, this test fails until that migration is
 * deliberately added to the reviewed list below - the same
 * "pre-production, fine to wipe" call V8/V9/V12 each document in their own
 * comments has to be made consciously every time, not slip in unnoticed.
 *
 * Confirmed by direct inspection of every file in db/migration (not just
 * the roadmap's own text, which named only V8 and V12): V9 also contains
 * two real TRUNCATE TABLE statements (password_reset_otps,
 * login_mfa_otps), same "pre-production, fine to wipe" rationale as V8.
 * V11 only mentions the word "truncate" in a comment explaining why it
 * does NOT need one - it has no actual TRUNCATE statement, so it is
 * deliberately excluded from the reviewed set below.
 */
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
                "V9__otp_client_application_scoping.sql",
                "V12__sub_permission_group_parent_fk.sql");
    }
}

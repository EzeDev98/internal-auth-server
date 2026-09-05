package com.internal.auth.migration;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Step 10B (part 2). The actual mechanical safeguard against a destructive
 * operation ever running against a real, populated database is Flyway's
 * own clean-disabled setting - flyway:clean drops every Flyway-managed
 * table outright, which is strictly worse than V8/V9/V12's own one-time,
 * already-applied, pre-production TRUNCATEs. Flyway 7+ already defaults
 * this to true, but relying on an unstated library default is exactly the
 * kind of implicit safety this project has repeatedly turned explicit
 * elsewhere (see the fail-closed app.service-role-assignment.allowed-roles
 * default, or V20's constraint backstop for a check-then-act race) - so
 * application-prod.properties now states it directly. This test locks
 * that line in place so it can't quietly disappear in a future edit.
 */
class FlywayCleanDisabledInProdTest {

    @Test
    void prodProfileExplicitlyDisablesFlywayClean() throws IOException {
        Properties prodProperties = new Properties();
        try (InputStream in = getClass().getClassLoader()
                .getResourceAsStream("application-prod.properties")) {
            assertThat(in).as("application-prod.properties must be on the classpath").isNotNull();
            prodProperties.load(in);
        }

        assertThat(prodProperties.getProperty("spring.flyway.clean-disabled"))
                .as("flyway:clean must never be able to run against a real, populated database")
                .isEqualTo("true");
    }
}

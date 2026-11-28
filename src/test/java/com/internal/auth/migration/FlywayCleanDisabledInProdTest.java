package com.internal.auth.migration;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/** Verifies Flyway clean is disabled in production. */
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

package com.internal.auth.migration;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.flywaydb.core.api.MigrationState;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Step 10A. Deliberately does NOT extend IntegrationTestBase: that class's
 * Postgres container is a static singleton shared (and reusable) across
 * every other IT class in this fork, so by the time most of those run it is
 * no longer empty - some earlier IT class already applied every migration
 * to it. This class starts its own, single-use Postgres container (no
 * withReuse) so "V1 through V21 from empty" is actually true here, not
 * just assumed.
 *
 * Two things are asserted:
 * 1) Flyway's own migration info shows all 21 versioned migrations applied
 *    successfully, in order, with none pending/failed/out-of-order.
 * 2) The resulting schema matches JPA entity expectations - enforced not by
 *    hand-rolling a separate schema comparison here, but by this test
 *    profile's own spring.jpa.hibernate.ddl-auto=validate
 *    (application-test.properties, "mirrors prod's schema-management
 *    strategy"): Hibernate's SchemaManagementTool runs a real validation
 *    pass against every mapped @Entity during context refresh and throws
 *    on any mismatch (missing/extra column, wrong type, wrong
 *    nullability), which would fail this test before the @Test method
 *    body even ran. Reaching the assertions below already proves that
 *    check passed against this exact, freshly-migrated schema.
 *
 * webEnvironment.MOCK (the @SpringBootTest default, named explicitly here
 * for the same reason IntegrationTestBase names its own choice): a real
 * embedded Tomcat is neither needed (no MockMvc/HTTP call in this test) nor
 * safe to add here - IntegrationTestBase's own contexts already bind
 * webEnvironment.DEFINED_PORT to port 8080 elsewhere in this same fork, and
 * this class's different container ports give it a different
 * @DynamicPropertySource fingerprint, so Spring's test-context cache cannot
 * reuse that context - it would build a second one. MOCK still satisfies
 * every @ConditionalOnWebApplication(type = SERVLET) bean this app defines
 * (including AuthorizationServerConfig's HttpSecurity-based beans), just
 * without opening a socket, so nothing here can collide with those.
 */
@ActiveProfiles("test")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
class FlywayMigrationChainIT {

    private static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
                    .withDatabaseName("internal_auth_migration_test")
                    .withUsername("test")
                    .withPassword("test");

    private static final GenericContainer<?> REDIS =
            new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
                    .withExposedPorts(6379);

    static {
        POSTGRES.start();
        REDIS.start();
    }

    @DynamicPropertySource
    static void registerContainerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);

        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
    }

    @Autowired
    private Flyway flyway;

    @Test
    void everyMigrationFromV1ThroughV21AppliesCleanlyToAnEmptyDatabase_andTheContextLoadingProvesSchemaMatchesEntities() {
        MigrationInfo[] applied = flyway.info().applied();

        List<String> appliedVersions = Arrays.stream(applied)
                .map(info -> info.getVersion().toString())
                .toList();

        assertThat(appliedVersions).containsExactly(
                "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21");
        assertThat(applied).extracting(MigrationInfo::getState).containsOnly(MigrationState.SUCCESS);
    }
}

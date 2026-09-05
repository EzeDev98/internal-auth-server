package com.internal.auth.testsupport;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Base class for every integration test in this suite. Starts one Postgres
 * and one Redis container per JVM fork (singleton container pattern - the
 * static fields are shared across every subclass, started once, and left
 * running for Testcontainers' Ryuk reaper to clean up on JVM exit rather
 * than stopped manually, so later test classes in the same fork reuse them
 * instead of paying container-startup cost per class).
 *
 * webEnvironment = DEFINED_PORT (fixed at 8080, matching
 * application.properties' base-url default) rather than RANDOM_PORT: this
 * app mints and verifies its own tokens against its own issuer
 * (WebSecurityConfig#jwtDecoder does a real HTTP GET to
 * {issuer}/oauth2/jwks), and app.self-issuer-uri/app.token-issuer-uri both
 * default to http://localhost:8080 - a random port would mint tokens whose
 * issuer doesn't match where the JWKS endpoint is actually listening.
 * Consequence: subclasses of this base class can't run in parallel JVM
 * forks on the same machine.
 *
 * Deliberately does NOT do per-test transactional rollback - this app's
 * services commit their own transactions independently (registration,
 * login, etc.), so a test-level @Transactional wrapping an HTTP call
 * wouldn't roll back what the controller under test already committed on
 * its own. Each test class is responsible for its own data cleanup
 * (typically a @BeforeEach truncating the tables it touches) - a shared
 * blanket strategy is left for a later step once more test classes exist
 * to see what pattern actually fits.
 */
@AutoConfigureMockMvc
@ActiveProfiles("test")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public abstract class IntegrationTestBase {

    protected static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
                    .withDatabaseName("internal_auth_test")
                    .withUsername("test")
                    .withPassword("test")
                    .withReuse(true);

    protected static final GenericContainer<?> REDIS =
            new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
                    .withExposedPorts(6379)
                    .withReuse(true);

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
    protected MockMvc mockMvc;
}

package com.internal.auth.feature.audit.listener;
import org.springframework.test.context.TestPropertySource;

import com.internal.auth.feature.audit.enums.AuditAction;
import com.internal.auth.feature.audit.event.UserLoggedInEvent;
import com.internal.auth.feature.audit.model.AuditLog;
import com.internal.auth.feature.audit.repository.AuditLogRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.modulith.events.IncompleteEventPublications;
import org.springframework.modulith.events.core.EventPublicationRegistry;
import org.springframework.modulith.test.ApplicationModuleTest;
import org.springframework.modulith.test.Scenario;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;

/** Module tests for the audit module and AuditEventListener. */
@ActiveProfiles("test")
@TestPropertySource(properties = "spring.autoconfigure.exclude=org.redisson.spring.starter.RedissonAutoConfigurationV4")
@ApplicationModuleTest
class AuditEventListenerModuleIT {

    private static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
                    .withDatabaseName("internal_auth_audit_module_test")
                    .withUsername("test")
                    .withPassword("test")
                    .withReuse(true);

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void registerContainerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @MockitoSpyBean
    private AuditLogRepository auditLogRepository;

    @Autowired
    private EventPublicationRegistry eventPublicationRegistry;

    @Autowired
    private IncompleteEventPublications incompleteEventPublications;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void resetState() {
        reset(auditLogRepository);
        jdbcTemplate.update("DELETE FROM audit_log");
        jdbcTemplate.update("DELETE FROM event_publication");
    }

    @Test
    void publishedLoginEvent_isPersistedAsAuditLogByTheListener(Scenario scenario) {
        UserLoggedInEvent event = new UserLoggedInEvent(101L, "moses.dev", 7L);

        scenario.publish(event)
                .andWaitForStateChange(auditLogRepository::findAll, logs -> !logs.isEmpty())
                .andVerify(logs -> {
                    assertThat(logs).hasSize(1);
                    AuditLog log = logs.get(0);
                    assertThat(log.getAction()).isEqualTo(AuditAction.LOGIN_SUCCESS.name());
                    assertThat(log.getActorUserId()).isEqualTo(101L);
                    assertThat(log.getActorUsername()).isEqualTo("moses.dev");
                    assertThat(log.getClientApplicationId()).isEqualTo(7L);
                });
    }

    @Test
    void crashMidProcessing_leavesAnIncompletePublication_thatResubmitReplaysOnRestart(Scenario scenario) throws InterruptedException {
        doThrow(new RuntimeException("simulated crash mid-processing"))
                .when(auditLogRepository).save(any());

        UserLoggedInEvent event = new UserLoggedInEvent(202L, "grace.dev", 7L);

        scenario.publish(event)
                .andWaitForStateChange(eventPublicationRegistry::findIncompletePublications, incomplete -> !incomplete.isEmpty())
                .andVerify(incomplete -> {
                    assertThat(incomplete).hasSize(1);
                    assertThat(auditLogRepository.findAll()).isEmpty();
                });

        reset(auditLogRepository);
        incompleteEventPublications.resubmitIncompletePublications(publication -> true);

        List<AuditLog> replayed = awaitAuditLogWrite();
        assertThat(replayed).hasSize(1);
        assertThat(replayed.get(0).getActorUsername()).isEqualTo("grace.dev");
        assertThat(eventPublicationRegistry.findIncompletePublications()).isEmpty();
    }

    private List<AuditLog> awaitAuditLogWrite() throws InterruptedException {
        for (int i = 0; i < 50; i++) {
            List<AuditLog> logs = auditLogRepository.findAll();
            if (!logs.isEmpty()) {
                return logs;
            }
            Thread.sleep(100);
        }
        return auditLogRepository.findAll();
    }
}

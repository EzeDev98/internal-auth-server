package com.internal.auth.common.util;

import com.internal.auth.common.exception.MaxAttemptsExceededException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Integration tests for RateLimiterService against a real Redis. */
@Testcontainers
class RateLimiterServiceIT {

    @Container
    private static final GenericContainer<?> REDIS =
            new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
                    .withExposedPorts(6379);

    private static RedissonClient redissonClient;
    private static RateLimiterService rateLimiterService;

    @BeforeAll
    static void setUpRedisson() {
        Config config = new Config();
        config.useSingleServer()
                .setAddress("redis://" + REDIS.getHost() + ":" + REDIS.getMappedPort(6379));
        redissonClient = Redisson.create(config);
        rateLimiterService = new RateLimiterService(redissonClient);
    }

    @AfterAll
    static void shutDownRedisson() {
        if (redissonClient != null) {
            redissonClient.shutdown();
        }
    }

    @Test
    void tripsExactlyAtTheConfiguredThreshold() {
        String key = "rate-limit-test:threshold:" + System.nanoTime();
        Duration window = Duration.ofSeconds(5);

        rateLimiterService.checkRateLimit(key, 3, window);
        rateLimiterService.checkRateLimit(key, 3, window);
        rateLimiterService.checkRateLimit(key, 3, window);

        assertThatThrownBy(() -> rateLimiterService.checkRateLimit(key, 3, window))
                .isInstanceOf(MaxAttemptsExceededException.class);
    }

    @Test
    void resetsOnceTheWindowFullyElapses() throws InterruptedException {
        String key = "rate-limit-test:reset:" + System.nanoTime();
        Duration window = Duration.ofSeconds(2);

        rateLimiterService.checkRateLimit(key, 1, window);
        assertThatThrownBy(() -> rateLimiterService.checkRateLimit(key, 1, window))
                .isInstanceOf(MaxAttemptsExceededException.class);

        Thread.sleep(window.plusSeconds(1).toMillis());

        rateLimiterService.checkRateLimit(key, 1, window);
    }

    @Test
    void bucketsAreIndependentPerKey() {
        String keyA = "rate-limit-test:bucket-a:" + System.nanoTime();
        String keyB = "rate-limit-test:bucket-b:" + System.nanoTime();
        Duration window = Duration.ofSeconds(5);

        rateLimiterService.checkRateLimit(keyA, 1, window);
        assertThatThrownBy(() -> rateLimiterService.checkRateLimit(keyA, 1, window))
                .isInstanceOf(MaxAttemptsExceededException.class);

        rateLimiterService.checkRateLimit(keyB, 1, window);
    }
}

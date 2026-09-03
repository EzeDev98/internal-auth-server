package com.internal.auth.config.redis;

import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * Step 11C: rebuilt on RedissonClient - the single Redis client this app
 * now uses everywhere (see RedissonConfig) - instead of a separate Spring
 * Data Redis / Lettuce RedisTemplate stack (RedisClientConnection /
 * RedisClientConfiguration, both removed). Same public method shapes as
 * before, so JwtSessionTrackingFilter (the only caller) needed no changes;
 * just backed by RBucket instead of RedisTemplate.opsForValue(), the same
 * primitive OtpResetEngine's cooldown buckets already use.
 */
@Service
@Slf4j
public class SessionStorage {

    private final RedissonClient redissonClient;

    public SessionStorage(RedissonClient redissonClient) {
        this.redissonClient = redissonClient;
    }

    public void putCache(String cacheName, Object key, Object value, long timeToLiveSeconds) {
        RBucket<Object> bucket = redissonClient.getBucket(cacheName + key);
        bucket.set(value, Duration.ofSeconds(timeToLiveSeconds));
    }

    public Object getCache(String cacheName, Object key) {
        return redissonClient.getBucket(cacheName + key).get();
    }

    public Object getCache(String cacheName) {
        return redissonClient.getBucket(cacheName).get();
    }

    public void removeCache(String cacheName, Object key) {
        redissonClient.getBucket(cacheName + key).delete();
    }
}

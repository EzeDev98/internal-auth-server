package com.internal.auth.config.redis;

import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;
import org.springframework.stereotype.Service;

import java.time.Duration;

/** Redisson-backed key-value cache used for session and OTP bookkeeping. */
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

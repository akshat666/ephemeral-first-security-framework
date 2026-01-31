package app.hideit.store;

import app.hideit.exception.BackendException;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

import java.net.URI;
import java.time.Duration;
import java.util.Optional;

/**
 * Redis storage backend with native TTL support.
 * Uses connection pooling for efficient resource management.
 */
public final class RedisBackend implements StorageBackend {

    private final JedisPool pool;
    private final String keyPrefix;

    /**
     * Creates a Redis backend from a URI.
     *
     * @param uri the Redis URI (e.g., "redis://localhost:6379")
     */
    public RedisBackend(String uri) {
        this(uri, "efsf:");
    }

    /**
     * Creates a Redis backend from a URI with a custom key prefix.
     *
     * @param uri the Redis URI
     * @param keyPrefix the prefix for all keys
     */
    public RedisBackend(String uri, String keyPrefix) {
        try {
            JedisPoolConfig config = new JedisPoolConfig();
            config.setMaxTotal(10);
            config.setMaxIdle(5);
            config.setMinIdle(1);
            config.setTestOnBorrow(true);

            this.pool = new JedisPool(config, URI.create(uri));
            this.keyPrefix = keyPrefix != null ? keyPrefix : "";
        } catch (Exception e) {
            throw new BackendException("Failed to connect to Redis: " + uri, e);
        }
    }

    /**
     * Creates a Redis backend with an existing JedisPool.
     *
     * @param pool the JedisPool
     * @param keyPrefix the prefix for all keys
     */
    public RedisBackend(JedisPool pool, String keyPrefix) {
        this.pool = pool;
        this.keyPrefix = keyPrefix != null ? keyPrefix : "";
    }

    @Override
    public void set(String key, String value, Duration ttl) {
        String fullKey = keyPrefix + key;
        try (Jedis jedis = pool.getResource()) {
            long seconds = ttl.getSeconds();
            if (seconds <= 0) {
                seconds = 1; // Minimum 1 second TTL
            }
            jedis.setex(fullKey, seconds, value);
        } catch (Exception e) {
            throw new BackendException("Redis SET failed for key: " + key, e);
        }
    }

    @Override
    public Optional<String> get(String key) {
        String fullKey = keyPrefix + key;
        try (Jedis jedis = pool.getResource()) {
            String value = jedis.get(fullKey);
            return Optional.ofNullable(value);
        } catch (Exception e) {
            throw new BackendException("Redis GET failed for key: " + key, e);
        }
    }

    @Override
    public boolean delete(String key) {
        String fullKey = keyPrefix + key;
        try (Jedis jedis = pool.getResource()) {
            return jedis.del(fullKey) > 0;
        } catch (Exception e) {
            throw new BackendException("Redis DEL failed for key: " + key, e);
        }
    }

    @Override
    public boolean exists(String key) {
        String fullKey = keyPrefix + key;
        try (Jedis jedis = pool.getResource()) {
            return jedis.exists(fullKey);
        } catch (Exception e) {
            throw new BackendException("Redis EXISTS failed for key: " + key, e);
        }
    }

    @Override
    public Optional<Duration> ttl(String key) {
        String fullKey = keyPrefix + key;
        try (Jedis jedis = pool.getResource()) {
            long seconds = jedis.ttl(fullKey);
            if (seconds < 0) {
                return Optional.empty(); // Key doesn't exist or has no TTL
            }
            return Optional.of(Duration.ofSeconds(seconds));
        } catch (Exception e) {
            throw new BackendException("Redis TTL failed for key: " + key, e);
        }
    }

    @Override
    public String getBackendName() {
        return "redis";
    }

    @Override
    public void close() {
        if (pool != null && !pool.isClosed()) {
            pool.close();
        }
    }

    /**
     * Checks if the Redis connection is healthy.
     *
     * @return true if the connection is healthy
     */
    public boolean isHealthy() {
        try (Jedis jedis = pool.getResource()) {
            return "PONG".equals(jedis.ping());
        } catch (Exception e) {
            return false;
        }
    }
}

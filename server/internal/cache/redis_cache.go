package cache

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

type URLCache struct {
	client *redis.Client
	ttl    time.Duration
}

type CacheEntry struct {
	IsMalicious bool      `json:"is_malicious"`
	CheckedAt   time.Time `json:"checked_at"`
}

func NewURLCache(addr, password string) *URLCache {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       0,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		log.Printf("Warning: Redis connection failed: %v. Continuing without cache.", err)
	}

	return &URLCache{
		client: client,
		ttl:    24 * time.Hour,
	}
}

func (c *URLCache) Get(ctx context.Context, url string) (bool, bool) {
	val, err := c.client.Get(ctx, url).Result()
	if err == redis.Nil {
		return false, false
	}
	if err != nil {
		log.Printf("Redis error during Get: %v", err)
		return false, false
	}

	var entry CacheEntry
	if err := json.Unmarshal([]byte(val), &entry); err != nil {
		log.Printf("Cache entry deserialization failed: %v", err)
		return false, false
	}
	return entry.IsMalicious, true
}

func (c *URLCache) Set(ctx context.Context, url string, isMalicious bool) error {
	entry := &CacheEntry{
		IsMalicious: isMalicious,
		CheckedAt:   time.Now(),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	err = c.client.Set(ctx, url, data, c.ttl).Err()
	if err != nil {
		log.Printf("Redis error during Set: %v", err)
	}
	return err
}

func (c *URLCache) Close() error {
	return c.client.Close()
}

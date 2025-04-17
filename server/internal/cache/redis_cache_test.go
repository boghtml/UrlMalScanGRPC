package cache

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
)

func TestRedisCache(t *testing.T) {

	s, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}
	defer s.Close()

	cache := NewURLCache(s.Addr(), "")

	ctx := context.Background()

	safeURL := "https://example.com"
	maliciousURL := "https://malicious.com"

	t.Run("Get non-existent entry", func(t *testing.T) {
		isMalicious, reason, found := cache.Get(ctx, "non-existent-url")
		assert.False(t, found)
		assert.False(t, isMalicious)
		assert.Empty(t, reason)
	})

	t.Run("Set and get safe URL", func(t *testing.T) {
		err := cache.Set(ctx, safeURL, false, "")
		assert.NoError(t, err)

		isMalicious, reason, found := cache.Get(ctx, safeURL)
		assert.True(t, found)
		assert.False(t, isMalicious)
		assert.Empty(t, reason)
	})
	t.Run("Set and get malicious URL", func(t *testing.T) {
		expectedReason := "Domain is blacklisted"
		err := cache.Set(ctx, maliciousURL, true, expectedReason)
		assert.NoError(t, err)

		isMalicious, reason, found := cache.Get(ctx, maliciousURL)
		assert.True(t, found)
		assert.True(t, isMalicious)
		assert.Equal(t, expectedReason, reason)
	})

	t.Run("Check expiration", func(t *testing.T) {
		expiringURL := "https://expiring.com"
		err := cache.Set(ctx, expiringURL, true, "test reason")
		assert.NoError(t, err)

		isMalicious, _, found := cache.Get(ctx, expiringURL)
		assert.True(t, found)
		assert.True(t, isMalicious)

		s.FastForward(25 * time.Hour)

		_, _, found = cache.Get(ctx, expiringURL)
		assert.False(t, found)
	})

	t.Run("Update existing entry", func(t *testing.T) {
		updatingURL := "https://updating.com"

		err := cache.Set(ctx, updatingURL, false, "")
		assert.NoError(t, err)

		isMalicious, _, found := cache.Get(ctx, updatingURL)
		assert.True(t, found)
		assert.False(t, isMalicious)

		newReason := "Suspicious content found"
		err = cache.Set(ctx, updatingURL, true, newReason)
		assert.NoError(t, err)

		isMalicious, reason, found := cache.Get(ctx, updatingURL)
		assert.True(t, found)
		assert.True(t, isMalicious)
		assert.Equal(t, newReason, reason)
	})
}

func TestRedisErrors(t *testing.T) {

	cache := NewURLCache("invalid-addr:6379", "")

	ctx := context.Background()

	t.Run("Get with unavailable Redis", func(t *testing.T) {
		isMalicious, reason, found := cache.Get(ctx, "some-url")
		assert.False(t, found)
		assert.False(t, isMalicious)
		assert.Empty(t, reason)
	})

	t.Run("Set with unavailable Redis", func(t *testing.T) {
		err := cache.Set(ctx, "some-url", true, "test reason")
		assert.Error(t, err)
	})
}

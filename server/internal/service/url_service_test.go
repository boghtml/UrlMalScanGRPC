package service

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockURLCache struct {
	mock.Mock
}

func (m *MockURLCache) Get(ctx context.Context, url string) (bool, string, bool) {
	args := m.Called(ctx, url)
	return args.Bool(0), args.String(1), args.Bool(2)
}

func (m *MockURLCache) Set(ctx context.Context, url string, isMalicious bool, reason string) error {
	args := m.Called(ctx, url, isMalicious, reason)
	return args.Error(0)
}

func (m *MockURLCache) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestCheckURL(t *testing.T) {
	testCases := []struct {
		name         string
		url          string
		cached       bool
		cacheMal     bool
		cacheReason  string
		expectMal    bool
		expectReason string
		expectErr    bool
	}{
		{
			name:         "Safe URL",
			url:          "https://example.com",
			cached:       false,
			expectMal:    false,
			expectReason: "",
			expectErr:    false,
		},
		{
			name:         "Malicious URL from cache",
			url:          "https://malicious.com",
			cached:       true,
			cacheMal:     true,
			cacheReason:  "The domain is blacklisted",
			expectMal:    true,
			expectReason: "The domain is blacklisted",
			expectErr:    false,
		},
		{
			name:         "Malicious URL not cached",
			url:          "https://malware.com/download.exe",
			cached:       false,
			expectMal:    true,
			expectReason: "The URL contains a link to a suspicious file type",
			expectErr:    false,
		},
		{
			name:         "URL with suspicious extension",
			url:          "https://example.com/file.exe",
			cached:       false,
			expectMal:    true,
			expectReason: "The URL contains a link to a suspicious file type",
			expectErr:    false,
		},
		{
			name:         "URL with IP address",
			url:          "http://192.168.1.1",
			cached:       false,
			expectMal:    true,
			expectReason: "The URL contains a direct link to an IP address",
			expectErr:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCache := new(MockURLCache)
			mockCache.On("Get", mock.Anything, tc.url).Return(tc.cacheMal, tc.cacheReason, tc.cached)

			if !tc.cached {
				mockCache.On("Set", mock.Anything, tc.url, tc.expectMal, tc.expectReason).Return(nil)
			}

			service := NewURLService(mockCache)

			isMalicious, reason, err := service.CheckURL(context.Background(), tc.url)

			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectMal, isMalicious)
				assert.Equal(t, tc.expectReason, reason)
			}

			mockCache.AssertExpectations(t)
		})
	}
}

func TestIsURLMalicious(t *testing.T) {
	mockCache := new(MockURLCache)
	service := NewURLService(mockCache)

	testCases := []struct {
		name         string
		url          string
		expectMal    bool
		expectReason string
	}{
		{
			name:         "Safe URL",
			url:          "https://example.com",
			expectMal:    false,
			expectReason: "",
		},
		{
			name:         "Blacklisted domain",
			url:          "https://malicious.com/page",
			expectMal:    true,
			expectReason: "The domain is blacklisted",
		},
		{
			name:         "Suspicious keyword",
			url:          "https://example.com/malware-download",
			expectMal:    true,
			expectReason: "The URL contains suspicious keywords",
		},
		{
			name:         "Suspicious extension",
			url:          "https://example.com/file.exe",
			expectMal:    true,
			expectReason: "The URL contains a link to a suspicious file type",
		},
		{
			name:         "IP address URL",
			url:          "http://192.168.1.1",
			expectMal:    true,
			expectReason: "The URL contains a direct link to an IP address",
		},
		{
			name:         "URL too long",
			url:          "https://example.com/" + strings.Repeat("a", 300),
			expectMal:    true,
			expectReason: "The URL is too long",
		},
		{
			name:         "Invalid URL",
			url:          "not-a-url",
			expectMal:    true,
			expectReason: "The URL format is invalid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isMalicious, reason := service.isURLMalicious(tc.url)
			assert.Equal(t, tc.expectMal, isMalicious)
			assert.Equal(t, tc.expectReason, reason)
		})
	}
}

func TestFilterHTML(t *testing.T) {
	mockCache := new(MockURLCache)

	htmlContent := `<html><body>
		<a href="https://example.com">Safe Link</a>
		<a href="https://malware.com/hack.exe">Malicious Link</a>
		<p>Visit our website at https://example.com for more information.</p>
		<p>Warning: do not visit https://malicious.com</p>
	</body></html>`

	mockCache.On("Get", mock.Anything, "https://example.com").Return(false, "", true)
	mockCache.On("Get", mock.Anything, "https://malware.com/hack.exe").Return(false, "", false)
	mockCache.On("Get", mock.Anything, "https://malicious.com").Return(false, "", false)
	mockCache.On("Set", mock.Anything, "https://malware.com/hack.exe", true, "The URL contains a link to a suspicious file type").Return(nil)
	mockCache.On("Set", mock.Anything, "https://malicious.com", true, "The domain is blacklisted").Return(nil)

	service := NewURLService(mockCache)

	filteredHTML, results, err := service.FilterHTML(context.Background(), htmlContent)

	assert.NoError(t, err)
	assert.NotEqual(t, htmlContent, filteredHTML)
	assert.Len(t, results, 3)

	var safeFound, maliciousExeFound, maliciousDomainFound bool
	for _, result := range results {
		url := result["url"].(string)
		isMalicious := result["is_malicious"].(bool)
		reason := result["reason"].(string)

		if url == "https://example.com" {
			assert.False(t, isMalicious)
			assert.Equal(t, "", reason)
			safeFound = true
		} else if url == "https://malware.com/hack.exe" {
			assert.True(t, isMalicious)
			assert.Equal(t, "The URL contains a link to a suspicious file type", reason)
			maliciousExeFound = true
		} else if url == "https://malicious.com" {
			assert.True(t, isMalicious)
			assert.Equal(t, "The domain is blacklisted", reason)
			maliciousDomainFound = true
		}
	}

	assert.True(t, safeFound, "Safe URL not found in results")
	assert.True(t, maliciousExeFound, "Malicious EXE URL not found in results")
	assert.True(t, maliciousDomainFound, "Malicious domain URL not found in results")

	assert.Contains(t, filteredHTML, `href="#" data-malicious="true"`)
	assert.Contains(t, filteredHTML, `[BLOCKED:`)
	assert.Contains(t, filteredHTML, `href="https://example.com"`)

	mockCache.AssertExpectations(t)
}

package service

import (
	"context"
	"log"
	"net/url"
	"regexp"
	"strings"

	"github.com/boghtml/url-filter-project/server/internal/cache"
)

type URLService struct {
	cache    *cache.URLCache
	urlRegex *regexp.Regexp

	blacklist            []string
	suspiciousPatterns   []string
	suspiciousExtensions []string
	ipRegex              *regexp.Regexp
	maxURLLength         int
}

func NewURLService(redisCache *cache.URLCache) *URLService {
	regexPattern := `(https?://[^\s"'<>]+|www\.[^\s"'<>]+)`
	urlRegex, err := regexp.Compile(regexPattern)
	if err != nil {
		log.Fatalf("Failed to compile url regex: %v", err)
	}

	ipRegex, err := regexp.Compile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)
	if err != nil {
		log.Fatalf("Failed to compile ip regex: %v", err)
	}

	return &URLService{
		cache:                redisCache,
		urlRegex:             urlRegex,
		blacklist:            []string{"malicious.com", "phish.net", "bad.site", "malware.com", "trojan-download.com"},
		suspiciousPatterns:   []string{"phish", "hack", "malware", "trojan", "virus", "warez", "crack", "keygen"},
		suspiciousExtensions: []string{".exe", ".bat", ".dll", ".scr", ".vbs", ".ps1", ".cmd", ".msi"},
		ipRegex:              ipRegex,
		maxURLLength:         250,
	}
}

func (s *URLService) CheckURL(ctx context.Context, urlStr string) (bool, error) {
	if isMalicious, found := s.cache.Get(ctx, urlStr); found {
		log.Printf("Cache hit for URL %s: isMalicious=%v", urlStr, isMalicious)
		return isMalicious, nil
	}

	isMalicious := s.isURLMalicious(urlStr)
	log.Printf("Checked URL %s: isMalicious=%v", urlStr, isMalicious)

	if err := s.cache.Set(ctx, urlStr, isMalicious); err != nil {
		log.Printf("Failed to set cache for URL %s: %v", urlStr, err)
		return false, err
	}

	return isMalicious, nil
}

func (s *URLService) FilterHTML(ctx context.Context, html string) (string, []map[string]interface{}, error) {
	urls := s.urlRegex.FindAllString(html, -1)
	log.Printf("Found %d URLs in HTML: %v", len(urls), urls)
	filteredHTML := html

	uniqueURLs := make(map[string]bool)
	for _, url := range urls {
		uniqueURLs[url] = true
	}
	log.Printf("Unique URLs: %v", uniqueURLs)

	results := make([]map[string]interface{}, 0)

	for url := range uniqueURLs {
		isMalicious, err := s.CheckURL(ctx, url)
		if err != nil {
			log.Printf("Error checking URL %s: %v", url, err)
			return "", nil, err
		}

		results = append(results, map[string]interface{}{
			"url":          url,
			"is_malicious": isMalicious,
		})

		if isMalicious {
			replacement := `<span class="blocked-url" data-original="` + url + `">[BLOCKED]</span>`
			escapedURL := regexp.QuoteMeta(url)

			urlRegex := regexp.MustCompile(`(href|src)=["']` + escapedURL + `["']`)
			filteredHTML = urlRegex.ReplaceAllString(filteredHTML, `$1="#" data-malicious="true" data-original-url="`+url+`"`)

			textRegex := regexp.MustCompile(escapedURL)
			filteredHTML = textRegex.ReplaceAllString(filteredHTML, replacement)
			log.Printf("Replaced malicious URL %s in HTML", url)
		}
	}

	log.Printf("Filtered HTML: %s", filteredHTML)
	return filteredHTML, results, nil
}

func (s *URLService) isURLMalicious(urlStr string) bool {
	if len(urlStr) > s.maxURLLength {
		log.Printf("URL %s is too long (%d > %d)", urlStr, len(urlStr), s.maxURLLength)
		return true
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		log.Printf("Invalid URL %s: %v", urlStr, err)
		return true
	}

	host := parsedURL.Hostname()
	urlLower := strings.ToLower(urlStr)

	for _, badDomain := range s.blacklist {
		if strings.Contains(host, badDomain) {
			log.Printf("URL %s matches blacklist domain %s", urlStr, badDomain)
			return true
		}
	}

	for _, pattern := range s.suspiciousPatterns {
		if strings.Contains(urlLower, pattern) {
			log.Printf("URL %s contains suspicious pattern %s", urlStr, pattern)
			return true
		}
	}

	for _, ext := range s.suspiciousExtensions {
		if strings.HasSuffix(strings.ToLower(parsedURL.Path), ext) {
			log.Printf("URL %s has suspicious extension %s", urlStr, ext)
			return true
		}
	}

	if s.ipRegex.MatchString(host) {
		log.Printf("URL %s uses IP address %s", urlStr, host)
		return true
	}

	return false
}

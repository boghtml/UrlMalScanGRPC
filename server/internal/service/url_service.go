package service

import (
	"context"
	"log"
	"net/url"
	"regexp"
	"strings"

	"github.com/boghtml/url-filter-project/server/internal/cache"
)

type URLServiceIface interface {
	CheckURL(ctx context.Context, url string) (bool, string, error)
	FilterHTML(ctx context.Context, html string) (string, []map[string]interface{}, error)
}

type URLService struct {
	cache    cache.URLCacheIface
	urlRegex *regexp.Regexp

	blacklist            []string
	suspiciousPatterns   []string
	suspiciousExtensions []string
	ipRegex              *regexp.Regexp
	maxURLLength         int
}

func NewURLService(c cache.URLCacheIface) *URLService {
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
		cache:                c,
		urlRegex:             urlRegex,
		blacklist:            []string{"malicious.com", "phish.net", "bad.site", "malware.com", "trojan-download.com"},
		suspiciousPatterns:   []string{"phish", "hack", "malware", "trojan", "virus", "warez", "crack", "keygen"},
		suspiciousExtensions: []string{".exe", ".bat", ".dll", ".scr", ".vbs", ".ps1", ".cmd", ".msi"},
		ipRegex:              ipRegex,
		maxURLLength:         250,
	}
}

func (s *URLService) CheckURL(ctx context.Context, urlStr string) (bool, string, error) {
	if isMalicious, reason, found := s.cache.Get(ctx, urlStr); found {
		log.Printf("Cache hit for URL %s: isMalicious=%v, reason=%s", urlStr, isMalicious, reason)
		return isMalicious, reason, nil
	}

	isMalicious, reason := s.isURLMalicious(urlStr)
	log.Printf("Checked URL %s: isMalicious=%v, reason=%s", urlStr, isMalicious, reason)

	if err := s.cache.Set(ctx, urlStr, isMalicious, reason); err != nil {
		log.Printf("Failed to set cache for URL %s: %v", urlStr, err)
		return isMalicious, reason, err
	}

	return isMalicious, reason, nil
}

func (s *URLService) FilterHTML(ctx context.Context, html string) (string, []map[string]interface{}, error) {
	urls := s.urlRegex.FindAllString(html, -1)
	log.Printf("Found %d URLs in HTML", len(urls))
	filteredHTML := html

	uniqueURLs := make(map[string]bool)
	for _, url := range urls {
		uniqueURLs[url] = true
	}
	log.Printf("Unique URLs count: %d", len(uniqueURLs))

	results := make([]map[string]interface{}, 0)

	for url := range uniqueURLs {
		isMalicious, reason, err := s.CheckURL(ctx, url)
		if err != nil {
			log.Printf("Error checking URL %s: %v", url, err)
			return "", nil, err
		}

		results = append(results, map[string]interface{}{
			"url":          url,
			"is_malicious": isMalicious,
			"reason":       reason,
		})

		if isMalicious {
			replacement := `<span class="blocked-url" data-original="` + url + `" data-reason="` + reason + `">[BLOCKED: ` + reason + `]</span>`
			escapedURL := regexp.QuoteMeta(url)

			urlRegex := regexp.MustCompile(`(href|src)=["']` + escapedURL + `["']`)
			filteredHTML = urlRegex.ReplaceAllString(filteredHTML, `$1="#" data-malicious="true" data-original-url="`+url+`" title="`+reason+`"`)

			textRegex := regexp.MustCompile(escapedURL)
			filteredHTML = textRegex.ReplaceAllString(filteredHTML, replacement)
			log.Printf("Replaced malicious URL %s in HTML", url)
		}
	}

	if len(filteredHTML) > 100 {
		log.Printf("Filtered HTML: %.100s...", filteredHTML)
	} else {
		log.Printf("Filtered HTML: %s", filteredHTML)
	}

	return filteredHTML, results, nil
}

func (s *URLService) isURLMalicious(urlStr string) (bool, string) {
	if len(urlStr) > s.maxURLLength {
		reason := "The URL is too long"
		log.Printf("URL %s is too long (%d > %d): %s", urlStr, len(urlStr), s.maxURLLength, reason)
		return true, reason
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		reason := "The URL format is invalid"
		log.Printf("Invalid URL %s: %v: %s", urlStr, err, reason)
		return true, reason
	}

	host := parsedURL.Hostname()
	urlLower := strings.ToLower(urlStr)

	for _, ext := range s.suspiciousExtensions {
		if strings.HasSuffix(strings.ToLower(parsedURL.Path), ext) {
			reason := "The URL contains a link to a suspicious file type"
			log.Printf("URL %s has suspicious extension %s: %s", urlStr, ext, reason)
			return true, reason
		}
	}

	for _, badDomain := range s.blacklist {
		if strings.Contains(host, badDomain) {
			reason := "The domain is blacklisted"
			log.Printf("URL %s matches blacklist domain %s: %s", urlStr, badDomain, reason)
			return true, reason
		}
	}

	for _, pattern := range s.suspiciousPatterns {
		if strings.Contains(urlLower, pattern) {
			reason := "The URL contains suspicious keywords"
			log.Printf("URL %s contains suspicious pattern %s: %s", urlStr, pattern, reason)
			return true, reason
		}
	}

	if s.ipRegex.MatchString(host) {
		reason := "The URL contains a direct link to an IP address"
		log.Printf("URL %s uses IP address %s: %s", urlStr, host, reason)
		return true, reason
	}

	return false, ""
}

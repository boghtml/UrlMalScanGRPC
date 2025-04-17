package handler

import (
	"context"
	"testing"

	pb "github.com/boghtml/url-filter-project/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockURLService struct {
	mock.Mock
}

func (m *MockURLService) CheckURL(ctx context.Context, url string) (bool, string, error) {
	args := m.Called(ctx, url)
	return args.Bool(0), args.String(1), args.Error(2)
}

func (m *MockURLService) FilterHTML(ctx context.Context, html string) (string, []map[string]interface{}, error) {
	args := m.Called(ctx, html)
	return args.String(0), args.Get(1).([]map[string]interface{}), args.Error(2)
}

func TestCheckURL(t *testing.T) {
	testCases := []struct {
		name      string
		url       string
		malicious bool
		reason    string
		expectErr bool
	}{
		{
			name:      "Safe URL",
			url:       "https://example.com",
			malicious: false,
			reason:    "",
			expectErr: false,
		},
		{
			name:      "Malicious URL",
			url:       "https://malicious.com",
			malicious: true,
			reason:    "The domain is blacklisted",
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			mockService := new(MockURLService)

			mockService.On("CheckURL", mock.Anything, tc.url).Return(tc.malicious, tc.reason, nil)

			handler := NewURLHandler(mockService)

			req := &pb.CheckURLRequest{
				Url: tc.url,
			}

			resp, err := handler.CheckURL(context.Background(), req)

			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, tc.url, resp.Url)
				assert.Equal(t, tc.malicious, resp.IsMalicious)
				assert.Equal(t, tc.reason, resp.Reason)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestFilterHTML(t *testing.T) {

	htmlContent := "<html><body>Test content</body></html>"
	filteredHTML := "<html><body>Filtered content</body></html>"

	results := []map[string]interface{}{
		{
			"url":          "https://example.com",
			"is_malicious": false,
			"reason":       "",
		},
		{
			"url":          "https://malicious.com",
			"is_malicious": true,
			"reason":       "The domain is blacklisted",
		},
	}

	mockService := new(MockURLService)

	mockService.On("FilterHTML", mock.Anything, htmlContent).Return(filteredHTML, results, nil)

	handler := NewURLHandler(mockService)

	req := &pb.FilterHTMLRequest{
		Html: htmlContent,
	}

	resp, err := handler.FilterHTML(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, filteredHTML, resp.FilteredHtml)
	assert.Len(t, resp.UrlResults, 2)

	assert.Equal(t, "https://example.com", resp.UrlResults[0].Url)
	assert.False(t, resp.UrlResults[0].IsMalicious)
	assert.Equal(t, "", resp.UrlResults[0].Reason)

	assert.Equal(t, "https://malicious.com", resp.UrlResults[1].Url)
	assert.True(t, resp.UrlResults[1].IsMalicious)
	assert.Equal(t, "The domain is blacklisted", resp.UrlResults[1].Reason)

	mockService.AssertExpectations(t)
}

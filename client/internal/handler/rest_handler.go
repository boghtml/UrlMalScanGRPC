package handler

import (
	"io/ioutil"
	"log"
	"net/http"

	"github.com/boghtml/url-filter-project/client/internal/grpc_client"
	pb "github.com/boghtml/url-filter-project/proto"
	"github.com/gin-gonic/gin"
)

type RESTHandler struct {
	urlClient *grpc_client.URLClient
}

func NewRESTHandler(urlClient *grpc_client.URLClient) *RESTHandler {
	return &RESTHandler{urlClient: urlClient}
}

type URLCheckRequest struct {
	URL string `json:"url" binding:"required"`
}

type URLCheckResponse struct {
	URL         string `json:"url"`
	IsMalicious bool   `json:"is_malicious"`
	Reason      string `json:"reason,omitempty"`
}

func (h *RESTHandler) CheckURL(c *gin.Context) {
	var req URLCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Error binding JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("Received CheckURL request for URL: %s", req.URL)

	resp, err := h.urlClient.CheckURL(req.URL)
	if err != nil {
		log.Printf("Error checking URL via gRPC: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Printf("URL checked: %s, Is malicious: %t, Reason: %s",
		resp.Url, resp.IsMalicious, resp.Reason)

	c.JSON(http.StatusOK, URLCheckResponse{
		URL:         resp.Url,
		IsMalicious: resp.IsMalicious,
		Reason:      resp.Reason,
	})
}

type FilterHTMLResponse struct {
	FilteredHTML string             `json:"filtered_html"`
	URLResults   []URLCheckResponse `json:"url_results"`
}

func (h *RESTHandler) FilterHTML(c *gin.Context) {
	file, err := c.FormFile("html_file")
	if err != nil {
		log.Printf("Error getting HTML file: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "HTML file not provided"})
		return
	}

	log.Printf("Received FilterHTML request with file: %s", file.Filename)

	openedFile, err := file.Open()
	if err != nil {
		log.Printf("Error opening file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not open file"})
		return
	}
	defer openedFile.Close()

	htmlContent, err := ioutil.ReadAll(openedFile)
	if err != nil {
		log.Printf("Error reading file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read file"})
		return
	}

	log.Printf("HTML file content length: %d bytes", len(htmlContent))

	resp, err := h.urlClient.FilterHTMLURLs(string(htmlContent))
	if err != nil {
		log.Printf("Error filtering HTML via gRPC: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	urlResults := make([]URLCheckResponse, 0, len(resp.UrlResults))
	for _, result := range resp.UrlResults {
		urlResults = append(urlResults, URLCheckResponse{
			URL:         result.Url,
			IsMalicious: result.IsMalicious,
			Reason:      result.Reason,
		})
	}

	log.Printf("HTML filtered. Found %d URLs, %d of them malicious",
		len(resp.UrlResults),
		countMalicious(resp.UrlResults))

	c.JSON(http.StatusOK, FilterHTMLResponse{
		FilteredHTML: resp.FilteredHtml,
		URLResults:   urlResults,
	})
}

func countMalicious(results []*pb.URLResult) int {
	count := 0
	for _, result := range results {
		if result.IsMalicious {
			count++
		}
	}
	return count
}

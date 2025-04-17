package handler

import (
	"context"
	"log"

	pb "github.com/boghtml/url-filter-project/proto"
	"github.com/boghtml/url-filter-project/server/internal/service"
)

type URLHandler struct {
	pb.UnimplementedURLServiceServer
	urlService *service.URLService
}

func NewURLHandler(urlService *service.URLService) *URLHandler {
	return &URLHandler{urlService: urlService}
}

func (h *URLHandler) CheckURL(ctx context.Context, req *pb.CheckURLRequest) (*pb.CheckURLResponse, error) {
	log.Printf("Received request to verify URL: %s", req.Url)

	isMalicious, reason, err := h.urlService.CheckURL(ctx, req.Url)
	if err != nil {
		log.Printf("Error while checking URL: %v", err)
		return nil, err
	}

	log.Printf("URL %s checked, result: %t, reason: %s", req.Url, isMalicious, reason)
	return &pb.CheckURLResponse{
		Url:         req.Url,
		IsMalicious: isMalicious,
		Reason:      reason,
	}, nil
}

func (h *URLHandler) FilterHTML(ctx context.Context, req *pb.FilterHTMLRequest) (*pb.FilterHTMLResponse, error) {
	log.Printf("Received request to filter HTML (length: %d bytes)", len(req.Html))
	filteredHTML, results, err := h.urlService.FilterHTML(ctx, req.Html)
	if err != nil {
		log.Printf("Error while filtering HTML: %v", err)
		return nil, err
	}

	urlResults := make([]*pb.URLResult, 0, len(results))
	for _, result := range results {
		urlResults = append(urlResults, &pb.URLResult{
			Url:         result["url"].(string),
			IsMalicious: result["is_malicious"].(bool),
			Reason:      result["reason"].(string),
		})
	}

	log.Printf("HTML filtered, found %d URLs, returning response", len(urlResults))
	return &pb.FilterHTMLResponse{
		FilteredHtml: filteredHTML,
		UrlResults:   urlResults,
	}, nil
}

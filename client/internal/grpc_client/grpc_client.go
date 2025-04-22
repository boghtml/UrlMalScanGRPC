package grpc_client

import (
	"context"
	"log"
	"time"

	pb "github.com/boghtml/url-filter-project/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type URLClient struct {
	client pb.URLServiceClient
	conn   *grpc.ClientConn
}

func NewURLClient(serverAddr string) (*URLClient, error) {
	log.Printf("Connecting to gRPC server at %s", serverAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock())

	if err != nil {
		log.Printf("Failed to connect to gRPC server: %v", err)
		return nil, err
	}

	log.Printf("Successfully connected to gRPC server at %s", serverAddr)
	client := pb.NewURLServiceClient(conn)

	return &URLClient{
		client: client,
		conn:   conn,
	}, nil
}

func (c *URLClient) CheckURL(url string) (*pb.CheckURLResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Printf("Sending CheckURL request for URL: %s", url)
	response, err := c.client.CheckURL(ctx, &pb.CheckURLRequest{
		Url: url,
	})

	if err != nil {
		log.Printf("Error calling CheckURL: %v", err)
		return nil, err
	}

	log.Printf("Received CheckURL response: URL=%s, IsMalicious=%t, Reason=%s",
		response.Url, response.IsMalicious, response.Reason)
	return response, nil
}

func (c *URLClient) FilterHTMLURLs(htmlContent string) (*pb.FilterHTMLResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Printf("Sending FilterHTML request with HTML content length: %d", len(htmlContent))
	response, err := c.client.FilterHTML(ctx, &pb.FilterHTMLRequest{
		Html: htmlContent,
	})

	if err != nil {
		log.Printf("Error calling FilterHTML: %v", err)
		return nil, err
	}

	log.Printf("Received FilterHTML response with filtered HTML length: %d and %d URL results",
		len(response.FilteredHtml), len(response.UrlResults))
	return response, nil
}

func (c *URLClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

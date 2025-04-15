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

	var conn *grpc.ClientConn
	var err error

	for i := 0; i < 5; i++ {
		log.Printf("Trying to connect to gRPC server at %s (attempt %d)", serverAddr, i+1)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		conn, err = grpc.DialContext(ctx, serverAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock())

		cancel()

		if err == nil {
			log.Printf("Successfully connected to gRPC server at %s", serverAddr)
			break
		}

		log.Printf("Failed to connect to gRPC server: %v. Retrying...", err)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		return nil, err
	}

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

	log.Printf("Received CheckURL response: %+v", response)
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

	log.Printf("Received FilterHTML response with filtered HTML length: %d", len(response.FilteredHtml))
	return response, nil
}

func (c *URLClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

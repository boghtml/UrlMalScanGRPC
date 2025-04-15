package main

import (
	"log"
	"os"

	"github.com/boghtml/url-filter-project/client/internal/grpc_client"
	"github.com/boghtml/url-filter-project/client/internal/handler"
	"github.com/gin-gonic/gin"
)

func main() {
	port := getEnv("PORT", "8080")
	grpcServerAddr := getEnv("GRPC_SERVER_ADDR", "server:50051")

	urlClient, err := grpc_client.NewURLClient(grpcServerAddr)
	if err != nil {
		log.Fatalf("Failed to create gRPC client: %v", err)
	}
	defer urlClient.Close()

	restHandler := handler.NewRESTHandler(urlClient)

	router := gin.Default()

	router.POST("/api/check-url", restHandler.CheckURL)
	router.POST("/api/filter-html", restHandler.FilterHTML)

	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "URL Checker API",
			"endpoints": []string{
				"POST /api/check-url - Checks URL for maliciousness",
				"POST /api/filter-html - Filters HTML from malicious URLs",
			},
		})
	})

	log.Printf("REST API server running on :%s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

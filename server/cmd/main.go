package main

import (
	"log"
	"net"
	"os"

	pb "github.com/boghtml/url-filter-project/proto"
	"github.com/boghtml/url-filter-project/server/internal/cache"
	"github.com/boghtml/url-filter-project/server/internal/handler"
	"github.com/boghtml/url-filter-project/server/internal/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {

	port := getEnv("PORT", "50051")
	redisAddr := getEnv("REDIS_ADDR", "redis:6379")
	redisPassword := getEnv("REDIS_PASSWORD", "")

	redisCache := cache.NewURLCache(redisAddr, redisPassword)

	urlService := service.NewURLService(redisCache)

	srv := grpc.NewServer()

	pb.RegisterURLServiceServer(srv, handler.NewURLHandler(urlService))

	reflection.Register(srv)

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	log.Printf("gRPC server running on :%s", port)
	log.Printf("Server is ready for grpcurl testing")
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

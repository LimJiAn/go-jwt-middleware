package main

import (
	"github.com/LimJiAn/go-jwt-middleware/middlewares"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		panic(err)
	}

	// Creates a router without any middleware by default
	r := gin.Default()

	// Custom middleware (JWT)
	r.Use(middlewares.ValidateJwtToken)

	// Listen and serve on 0.0.0.0:8080
	r.Run(":8080")
}

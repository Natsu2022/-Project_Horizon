package main

// ─── VA Scanner — HTTP Server Entry Point ────────────────────────────────────
//
// This is the process entry point (main). It bootstraps the Gin HTTP server
// and registers the two endpoints that the Python GUI communicates with:
//
//   POST /scan   → api.ScanHandler
//                  Accepts a JSON ScanRequest, runs the full scan pipeline,
//                  and returns a JSON ScanResponse.
//
//   GET  /health → inline handler
//                  Returns {"status":"ok"}. Used by start.sh to wait until
//                  the backend is ready before launching the GUI.
//
// Startup path:
//   ./start.sh  →  go build  →  ./va-server  →  main()  →  listen :5500
//
// Port: 5500 by default. Override with the VA_PORT environment variable.
// CORS: all origins allowed (necessary for the local Python/PyQt6 GUI).
// ─────────────────────────────────────────────────────────────────────────────

import (
	"log"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"vuln_assessment_app/internal/api"
)

// main initialises the Gin router, registers routes, then blocks on r.Run().
// All scan logic is in internal/api and downstream packages.
func main() {
	r := gin.Default()

	// CORS — allow GUI (localhost) to call the API
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type"},
		MaxAge:           12 * time.Hour,
	}))

	r.POST("/scan", api.ScanHandler)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	port := os.Getenv("VA_PORT")
	if port == "" {
		port = "5500"
	}

	log.Printf("Server running on http://127.0.0.1:%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal(err)
	}
}

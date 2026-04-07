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
	"strconv"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"vuln_assessment_app/internal/api"
	"vuln_assessment_app/internal/engine"
)

// main initialises the Gin router, registers routes, then blocks on r.Run().
// All scan logic is in internal/api and downstream packages.
func main() {
	// Redirect log output through the engine's log capture so [Engine] and
	// [ZAPScanner] lines are buffered and served by GET /logs.
	log.SetOutput(engine.NewLogCapture(os.Stderr))

	r := gin.Default()

	// CORS — allow GUI (localhost) to call the API
	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "OPTIONS"},
		AllowHeaders: []string{"Content-Type"},
		MaxAge:       12 * time.Hour,
	}))

	r.POST("/scan", api.ScanHandler)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	r.GET("/progress", func(c *gin.Context) {
		c.JSON(200, engine.GetProgress())
	})
	// POST /cancel — cancels the currently running scan immediately.
	// The GUI calls this when the user clicks Cancel so the backend stops
	// mid-flight without waiting for the HTTP client to close its connection.
	r.POST("/cancel", func(c *gin.Context) {
		engine.CancelCurrentScan()
		c.JSON(200, gin.H{"status": "cancelled"})
	})
	// GET /logs?after=N — returns backend log lines added since index N.
	// The GUI polls this every second to display [Engine] and [ZAPScanner]
	// messages in the log box without reopening the terminal.
	r.GET("/logs", func(c *gin.Context) {
		after, _ := strconv.Atoi(c.DefaultQuery("after", "0"))
		lines, next := engine.GetLogs(after)
		if lines == nil {
			lines = []string{}
		}
		c.JSON(200, gin.H{"lines": lines, "next": next})
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

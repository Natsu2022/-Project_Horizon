package report

import (
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"
)

// severityPDFColor returns RGB fill and text colors for a severity level.
func severityPDFColor(sev string) (fr, fg, fb, tr, tg, tb int) {
	switch sev {
	case "Critical":
		return 218, 54, 51, 255, 255, 255
	case "High":
		return 227, 136, 43, 255, 255, 255
	case "Medium":
		return 212, 172, 13, 0, 0, 0
	case "Low":
		return 31, 111, 235, 255, 255, 255
	default:
		return 50, 50, 50, 220, 220, 220
	}
}

// pdfTrunc truncates s to maxLen characters, appending "..." if needed.
func pdfTrunc(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// tr translates a string for fpdf (handles non-Latin-1 chars gracefully).
func tr(pdf *fpdf.Fpdf, s string) string {
	translator := pdf.UnicodeTranslatorFromDescriptor("")
	return translator(s)
}

func writePDF(path string, payload reportPayload) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.AliasNbPages("{nb}")

	// Page footer: page numbers
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(140, 140, 140)
		pdf.CellFormat(0, 6, fmt.Sprintf("Page %d of {nb}  |  Scan ID: %s", pdf.PageNo(), payload.ScanID), "", 0, "C", false, 0, "")
	})

	drawCoverPage(pdf, payload)
	drawSummaryTable(pdf, payload)
	drawDetailedFindings(pdf, payload)

	return pdf.OutputFileAndClose(path)
}

// drawCoverPage renders the cover page.
func drawCoverPage(pdf *fpdf.Fpdf, payload reportPayload) {
	pdf.AddPage()

	// Dark header bar
	pdf.SetFillColor(13, 17, 23)
	pdf.Rect(0, 0, 210, 48, "F")

	// Shield icon area + title
	pdf.SetFont("Helvetica", "B", 22)
	pdf.SetTextColor(230, 237, 243)
	pdf.SetXY(15, 14)
	pdf.CellFormat(180, 10, tr(pdf, "Vulnerability Assessment Report"), "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 11)
	pdf.SetTextColor(139, 148, 158)
	pdf.SetX(15)
	pdf.CellFormat(180, 8, tr(pdf, "Security Findings Summary"), "", 1, "L", false, 0, "")

	// Separator line
	pdf.SetDrawColor(48, 54, 61)
	pdf.SetLineWidth(0.5)
	pdf.Line(15, 54, 195, 54)

	// Metadata block
	pdf.SetFont("Helvetica", "", 11)
	pdf.SetTextColor(139, 148, 158)
	pdf.SetY(60)

	meta := [][]string{
		{"Target:", payload.Target},
		{"Scan ID:", payload.ScanID},
		{"Standard:", payload.OWASP},
		{"Generated:", payload.FinishedAt},
	}
	for _, row := range meta {
		pdf.SetX(15)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetTextColor(139, 148, 158)
		pdf.CellFormat(30, 7, tr(pdf, row[0]), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		pdf.SetTextColor(230, 237, 243)
		pdf.CellFormat(150, 7, tr(pdf, pdfTrunc(row[1], 80)), "", 1, "L", false, 0, "")
	}

	// Severity summary boxes
	pdf.SetY(pdf.GetY() + 14)
	severities := []struct {
		label string
		count int
	}{
		{"CRITICAL", payload.Stats.CriticalFindings},
		{"HIGH", payload.Stats.HighFindings},
		{"MEDIUM", payload.Stats.MediumFindings},
		{"LOW", payload.Stats.LowFindings},
	}

	boxW := 40.0
	boxH := 28.0
	startX := 15.0
	gap := 3.0
	y := pdf.GetY()

	for i, sev := range severities {
		x := startX + float64(i)*(boxW+gap)
		sevStr := strings.ToUpper(sev.label[:1]) + strings.ToLower(sev.label[1:])
		fr, fg, fb, txr, txg, txb := severityPDFColor(sevStr)
		pdf.SetFillColor(fr, fg, fb)
		pdf.SetDrawColor(fr, fg, fb)
		pdf.RoundedRect(x, y, boxW, boxH, 3, "1234", "F")

		pdf.SetFont("Helvetica", "B", 20)
		pdf.SetTextColor(txr, txg, txb)
		pdf.SetXY(x, y+3)
		pdf.CellFormat(boxW, 12, fmt.Sprintf("%d", sev.count), "", 1, "C", false, 0, "")

		pdf.SetFont("Helvetica", "", 8)
		pdf.SetXY(x, y+16)
		pdf.CellFormat(boxW, 6, sev.label, "", 1, "C", false, 0, "")
	}

	// URLs scanned box
	x := startX + 4*(boxW+gap)
	pdf.SetFillColor(22, 27, 34)
	pdf.SetDrawColor(48, 54, 61)
	pdf.RoundedRect(x, y, boxW, boxH, 3, "1234", "FD")
	pdf.SetFont("Helvetica", "B", 20)
	pdf.SetTextColor(139, 148, 158)
	pdf.SetXY(x, y+3)
	pdf.CellFormat(boxW, 12, fmt.Sprintf("%d", payload.Stats.ScannedURLs), "", 1, "C", false, 0, "")
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetXY(x, y+16)
	pdf.CellFormat(boxW, 6, "URLS", "", 1, "C", false, 0, "")
}

// drawSummaryTable renders the findings summary table on a new page.
func drawSummaryTable(pdf *fpdf.Fpdf, payload reportPayload) {
	pdf.AddPage()

	// Section header
	pdf.SetFillColor(22, 27, 34)
	pdf.Rect(15, 15, 180, 10, "F")
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(230, 237, 243)
	pdf.SetXY(18, 15)
	pdf.CellFormat(176, 10, tr(pdf, "Findings Summary"), "", 1, "L", false, 0, "")

	// Column widths: Module | Title | Severity | CVSS | URL
	colW := []float64{25, 65, 22, 15, 53}
	colH := 7.0
	headers := []string{"Module", "Title", "Severity", "CVSS", "URL"}

	drawTableHeader := func() {
		pdf.SetFillColor(30, 35, 45)
		pdf.SetTextColor(139, 148, 158)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetX(15)
		for i, h := range headers {
			pdf.CellFormat(colW[i], colH, h, "B", 0, "L", true, 0, "")
		}
		pdf.Ln(colH)
	}

	pdf.SetY(30)
	drawTableHeader()

	if len(payload.Findings) == 0 {
		pdf.SetFont("Helvetica", "I", 10)
		pdf.SetTextColor(139, 148, 158)
		pdf.SetX(15)
		pdf.CellFormat(180, 10, "No findings detected.", "", 1, "C", false, 0, "")
		return
	}

	for i, f := range payload.Findings {
		// Page break check
		if pdf.GetY() > 272 {
			pdf.AddPage()
			pdf.SetY(20)
			drawTableHeader()
		}

		// Alternating row background
		if i%2 == 0 {
			pdf.SetFillColor(22, 27, 34)
		} else {
			pdf.SetFillColor(13, 17, 23)
		}

		pdf.SetTextColor(230, 237, 243)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetX(15)

		// Module
		pdf.CellFormat(colW[0], colH, tr(pdf, pdfTrunc(f.Module, 14)), "", 0, "L", true, 0, "")
		// Title
		pdf.CellFormat(colW[1], colH, tr(pdf, pdfTrunc(f.Title, 38)), "", 0, "L", true, 0, "")
		// Severity (colored)
		fr, fg, fb, txr, txg, txb := severityPDFColor(f.Severity)
		pdf.SetFillColor(fr, fg, fb)
		pdf.SetTextColor(txr, txg, txb)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.CellFormat(colW[2], colH, f.Severity, "", 0, "C", true, 0, "")
		// CVSS
		if i%2 == 0 {
			pdf.SetFillColor(22, 27, 34)
		} else {
			pdf.SetFillColor(13, 17, 23)
		}
		pdf.SetTextColor(230, 237, 243)
		pdf.SetFont("Helvetica", "", 8)
		pdf.CellFormat(colW[3], colH, fmt.Sprintf("%.1f", f.CVSSScore), "", 0, "C", true, 0, "")
		// URL
		pdf.CellFormat(colW[4], colH, tr(pdf, pdfTrunc(f.TargetURL, 30)), "", 1, "L", true, 0, "")

		// Reset fill for next row's alternating color
		if i%2 == 0 {
			pdf.SetFillColor(22, 27, 34)
		} else {
			pdf.SetFillColor(13, 17, 23)
		}
	}
}

// drawDetailedFindings renders full details for each finding on a new page.
func drawDetailedFindings(pdf *fpdf.Fpdf, payload reportPayload) {
	if len(payload.Findings) == 0 {
		return
	}

	pdf.AddPage()

	// Section header
	pdf.SetFillColor(22, 27, 34)
	pdf.Rect(15, 15, 180, 10, "F")
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(230, 237, 243)
	pdf.SetXY(18, 15)
	pdf.CellFormat(176, 10, tr(pdf, "Detailed Findings"), "", 1, "L", false, 0, "")
	pdf.SetY(30)

	for _, f := range payload.Findings {
		// Page break before each finding if near the bottom
		if pdf.GetY() > 250 {
			pdf.AddPage()
			pdf.SetY(20)
		}

		startY := pdf.GetY()
		fr, fg, fb, txr, txg, txb := severityPDFColor(f.Severity)

		// Finding header bar
		pdf.SetFillColor(fr, fg, fb)
		pdf.Rect(15, startY, 4, 12, "F") // left color strip
		pdf.SetFillColor(22, 27, 34)
		pdf.Rect(19, startY, 176, 12, "F")

		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetTextColor(txr, txg, txb)
		pdf.SetXY(21, startY+1)
		pdf.CellFormat(20, 5, tr(pdf, "["+f.Severity+"]"), "", 0, "L", false, 0, "")

		pdf.SetTextColor(230, 237, 243)
		pdf.CellFormat(120, 5, tr(pdf, pdfTrunc(f.Title, 60)), "", 0, "L", false, 0, "")

		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(139, 148, 158)
		pdf.CellFormat(30, 5, fmt.Sprintf("CVSS: %.1f", f.CVSSScore), "", 1, "R", false, 0, "")

		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(139, 148, 158)
		pdf.SetX(21)
		pdf.CellFormat(180, 5, tr(pdf, "Module: "+f.Module+"  |  OWASP: "+pdfTrunc(f.OWASPCategory, 40)), "", 1, "L", false, 0, "")

		pdf.SetY(pdf.GetY() + 3)

		// Detail rows
		details := [][]string{
			{"URL", pdfTrunc(f.TargetURL, 90)},
			{"Description", pdfTrunc(f.Description, 300)},
			{"Evidence", pdfTrunc(f.Evidence, 200)},
			{"Recommendation", pdfTrunc(f.Recommendation, 300)},
			{"References", pdfTrunc(f.References, 120)},
			{"Detected At", f.DetectedAt},
		}

		for _, row := range details {
			if row[1] == "" {
				continue
			}
			if pdf.GetY() > 268 {
				pdf.AddPage()
				pdf.SetY(20)
			}
			pdf.SetX(15)
			pdf.SetFont("Helvetica", "B", 8)
			pdf.SetTextColor(139, 148, 158)
			pdf.CellFormat(32, 5, tr(pdf, row[0]+"  "), "", 0, "L", false, 0, "")

			// Evidence uses monospace-style box
			if row[0] == "Evidence" {
				pdf.SetFillColor(13, 17, 23)
				pdf.SetDrawColor(48, 54, 61)
				pdf.SetFont("Courier", "", 8)
				pdf.SetTextColor(121, 192, 255)
				pdf.MultiCell(145, 5, tr(pdf, row[1]), "1", "L", true)
			} else {
				pdf.SetFont("Helvetica", "", 8)
				pdf.SetTextColor(230, 237, 243)
				pdf.MultiCell(145, 5, tr(pdf, row[1]), "", "L", false)
			}
		}

		// Separator between findings
		pdf.SetDrawColor(48, 54, 61)
		pdf.SetLineWidth(0.3)
		pdf.Line(15, pdf.GetY()+3, 195, pdf.GetY()+3)
		pdf.SetY(pdf.GetY() + 8)
	}
}

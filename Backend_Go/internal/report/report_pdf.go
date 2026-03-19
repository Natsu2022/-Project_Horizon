package report

import (
	"fmt"
	"math"
	"strings"

	"github.com/go-pdf/fpdf"
)

// severityPDFColor returns RGB fill and text colors for a severity level.
func severityPDFColor(sev string) (fr, fg, fb, txr, txg, txb int) {
	switch sev {
	case "Critical":
		return 192, 38, 35, 255, 255, 255
	case "High":
		return 210, 100, 20, 255, 255, 255
	case "Medium":
		return 175, 125, 0, 255, 255, 255
	case "Low":
		return 25, 90, 190, 255, 255, 255
	default:
		return 90, 90, 90, 255, 255, 255
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

	// Page footer
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(110, 110, 110)
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

	// Dark navy header bar
	pdf.SetFillColor(25, 50, 95)
	pdf.Rect(0, 0, 210, 50, "F")

	// Title
	pdf.SetFont("Helvetica", "B", 22)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetXY(15, 13)
	pdf.CellFormat(180, 12, tr(pdf, "Vulnerability Assessment Report"), "", 1, "L", false, 0, "")

	// Subtitle
	pdf.SetFont("Helvetica", "", 11)
	pdf.SetTextColor(180, 205, 240)
	pdf.SetX(15)
	pdf.CellFormat(180, 8, tr(pdf, "Security Findings Summary"), "", 1, "L", false, 0, "")

	// Separator line
	pdf.SetDrawColor(180, 205, 240)
	pdf.SetLineWidth(0.5)
	pdf.Line(15, 56, 195, 56)

	// Metadata block
	pdf.SetY(62)
	meta := [][]string{
		{"Target:", payload.Target},
		{"Scan ID:", payload.ScanID},
		{"Standard:", payload.OWASP},
		{"Generated:", payload.FinishedAt},
	}
	for _, row := range meta {
		pdf.SetX(15)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetTextColor(70, 70, 70)
		pdf.CellFormat(32, 7, tr(pdf, row[0]), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		pdf.SetTextColor(15, 15, 15)
		pdf.CellFormat(148, 7, tr(pdf, pdfTrunc(row[1], 90)), "", 1, "L", false, 0, "")
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

	boxW := 34.0
	boxH := 28.0
	startX := 15.0
	gap := 2.5
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

		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetTextColor(txr, txg, txb)
		pdf.SetXY(x, y+16)
		pdf.CellFormat(boxW, 6, sev.label, "", 1, "C", false, 0, "")
	}

	// URLs scanned box
	x := startX + 4*(boxW+gap)
	pdf.SetFillColor(55, 90, 145)
	pdf.SetDrawColor(55, 90, 145)
	pdf.RoundedRect(x, y, boxW, boxH, 3, "1234", "F")
	pdf.SetFont("Helvetica", "B", 20)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetXY(x, y+3)
	pdf.CellFormat(boxW, 12, fmt.Sprintf("%d", payload.Stats.ScannedURLs), "", 1, "C", false, 0, "")
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetXY(x, y+16)
	pdf.CellFormat(boxW, 6, "URLS SCANNED", "", 1, "C", false, 0, "")
}

// drawSummaryTable renders the findings summary table on a new page.
func drawSummaryTable(pdf *fpdf.Fpdf, payload reportPayload) {
	pdf.AddPage()

	// Section header
	pdf.SetFillColor(25, 50, 95)
	pdf.Rect(15, 15, 180, 10, "F")
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetXY(18, 15)
	pdf.CellFormat(176, 10, tr(pdf, "Findings Summary"), "", 1, "L", false, 0, "")

	// Column widths: Module | Title | Severity | CVSS | URL
	// URL column maximised so URLs wrap rather than truncate
	colW := []float64{18, 48, 20, 12, 82}
	lineH := 5.0
	headers := []string{"Module", "Title", "Severity", "CVSS", "URL"}

	drawTableHeader := func() {
		pdf.SetFillColor(50, 80, 130)
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetX(15)
		for i, h := range headers {
			pdf.CellFormat(colW[i], lineH+2, h, "B", 0, "L", true, 0, "")
		}
		pdf.Ln(lineH + 2)
	}

	pdf.SetY(30)
	drawTableHeader()

	if len(payload.Findings) == 0 {
		pdf.SetFont("Helvetica", "I", 10)
		pdf.SetTextColor(80, 80, 80)
		pdf.SetX(15)
		pdf.CellFormat(180, 10, "No findings detected.", "", 1, "C", false, 0, "")
		return
	}

	// X positions for each column
	xMod := 15.0
	xTitle := xMod + colW[0]
	xSev := xTitle + colW[1]
	xCVSS := xSev + colW[2]
	xURL := xCVSS + colW[3]

	for i, f := range payload.Findings {
		// Estimate row height based on URL length (font 7pt, col width colW[4])
		pdf.SetFont("Helvetica", "", 7)
		urlLines := int(math.Ceil(pdf.GetStringWidth(f.TargetURL) / colW[4]))
		urlLines = max(urlLines, 1)
		rowH := float64(urlLines) * lineH

		// Page break check
		if pdf.GetY()+rowH > 272 {
			pdf.AddPage()
			pdf.SetY(20)
			drawTableHeader()
		}

		rowY := pdf.GetY()

		// Alternating row background (full row)
		if i%2 == 0 {
			pdf.SetFillColor(255, 255, 255)
		} else {
			pdf.SetFillColor(240, 244, 251)
		}
		pdf.Rect(xMod, rowY, 180, rowH, "F")

		// Severity badge background
		fr, fg, fb, txr, txg, txb := severityPDFColor(f.Severity)
		pdf.SetFillColor(fr, fg, fb)
		pdf.Rect(xSev, rowY, colW[2], rowH, "F")

		// Vertical center offset for single-line cells
		cellY := rowY + (rowH-lineH)/2

		// Module
		pdf.SetXY(xMod, cellY)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(15, 15, 15)
		pdf.CellFormat(colW[0], lineH, tr(pdf, pdfTrunc(f.Module, 12)), "", 0, "L", false, 0, "")

		// Title
		pdf.SetXY(xTitle, cellY)
		pdf.CellFormat(colW[1], lineH, tr(pdf, pdfTrunc(f.Title, 32)), "", 0, "L", false, 0, "")

		// Severity
		pdf.SetXY(xSev, cellY)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetTextColor(txr, txg, txb)
		pdf.CellFormat(colW[2], lineH, f.Severity, "", 0, "C", false, 0, "")

		// CVSS
		pdf.SetXY(xCVSS, cellY)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(15, 15, 15)
		pdf.CellFormat(colW[3], lineH, fmt.Sprintf("%.1f", f.CVSSScore), "", 0, "C", false, 0, "")

		// URL — full text, wraps automatically
		pdf.SetXY(xURL, rowY)
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetTextColor(15, 15, 15)
		pdf.MultiCell(colW[4], lineH, tr(pdf, f.TargetURL), "", "L", false)

		pdf.SetY(rowY + rowH)
	}
}

// drawDetailedFindings renders full details for each finding on a new page.
func drawDetailedFindings(pdf *fpdf.Fpdf, payload reportPayload) {
	if len(payload.Findings) == 0 {
		return
	}

	pdf.AddPage()

	// Section header
	pdf.SetFillColor(25, 50, 95)
	pdf.Rect(15, 15, 180, 10, "F")
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(255, 255, 255)
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

		// Finding header: left color strip + light header bar
		pdf.SetFillColor(fr, fg, fb)
		pdf.Rect(15, startY, 4, 14, "F")
		pdf.SetFillColor(232, 238, 248)
		pdf.Rect(19, startY, 176, 14, "F")

		// Severity badge
		pdf.SetFillColor(fr, fg, fb)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetTextColor(txr, txg, txb)
		pdf.SetXY(21, startY+2)
		pdf.CellFormat(22, 5, tr(pdf, " "+f.Severity+" "), "", 0, "C", true, 0, "")

		// Title
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetTextColor(15, 15, 15)
		pdf.CellFormat(112, 5, tr(pdf, " "+pdfTrunc(f.Title, 62)), "", 0, "L", false, 0, "")

		// CVSS score (right-aligned)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(25, 50, 95)
		pdf.CellFormat(28, 5, fmt.Sprintf("CVSS: %.1f", f.CVSSScore), "", 1, "R", false, 0, "")

		// Module & OWASP
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(60, 60, 60)
		pdf.SetX(21)
		pdf.CellFormat(174, 5, tr(pdf, "Module: "+f.Module+"  |  OWASP: "+pdfTrunc(f.OWASPCategory, 55)), "", 1, "L", false, 0, "")

		pdf.SetY(pdf.GetY() + 3)

		// Detail rows — full text (no truncation) so all information is shown
		details := [][]string{
			{"URL", f.TargetURL},
			{"CWE", strings.Join(f.CWEIDs, ", ")},
			{"Description", f.Description},
			{"Evidence", f.Evidence},
			{"Recommendation", f.Recommendation},
			{"References", f.References},
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
			pdf.SetTextColor(40, 75, 140)
			pdf.CellFormat(32, 5, tr(pdf, row[0]), "", 0, "L", false, 0, "")

			if row[0] == "Evidence" {
				// Monospace code box with light blue background
				pdf.SetFillColor(240, 245, 255)
				pdf.SetDrawColor(160, 190, 230)
				pdf.SetFont("Courier", "", 8)
				pdf.SetTextColor(20, 55, 120)
				pdf.MultiCell(143, 5, tr(pdf, row[1]), "1", "L", true)
			} else {
				pdf.SetFont("Helvetica", "", 8)
				pdf.SetTextColor(15, 15, 15)
				pdf.MultiCell(143, 5, tr(pdf, row[1]), "", "L", false)
			}
		}

		// Separator between findings
		pdf.SetDrawColor(170, 195, 230)
		pdf.SetLineWidth(0.3)
		pdf.Line(15, pdf.GetY()+3, 195, pdf.GetY()+3)
		pdf.SetY(pdf.GetY() + 8)
	}
}
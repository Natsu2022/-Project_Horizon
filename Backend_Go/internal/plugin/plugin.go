package plugin

import "context"

import "vuln_assessment_app/internal/model"

type ScannerPlugin interface {
	Name() string
	Scan(ctx context.Context, url model.URLInfo) []model.Finding
}

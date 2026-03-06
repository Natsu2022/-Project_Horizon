package report

import (
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"

	"vuln_assessment_app/internal/model"
)

type htmlFinding struct {
	ID             string
	Module         string
	Title          string
	Severity       string
	SevClass       string
	CVSSScore      string
	OWASPCategory  string
	TargetURL      string
	Evidence       string
	Description    string
	Recommendation string
	References     string
	DetectedAt     string
}

type moduleCount struct {
	Name  string
	Count int
}

type htmlReportData struct {
	ScanID      string
	Target      string
	OWASP       string
	GeneratedAt string
	Stats       model.ScanStats
	Modules     []moduleCount
	Findings    []htmlFinding
}

func writeHTML(path string, payload reportPayload) error {
	data := buildHTMLData(payload)
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, data)
}

func buildHTMLData(payload reportPayload) htmlReportData {
	moduleCounts := map[string]int{}
	findings := make([]htmlFinding, 0, len(payload.Findings))
	for _, f := range payload.Findings {
		moduleCounts[f.Module]++
		findings = append(findings, htmlFinding{
			ID:             f.ID,
			Module:         f.Module,
			Title:          f.Title,
			Severity:       f.Severity,
			SevClass:       strings.ToLower(f.Severity),
			CVSSScore:      fmt.Sprintf("%.1f", f.CVSSScore),
			OWASPCategory:  f.OWASPCategory,
			TargetURL:      f.TargetURL,
			Evidence:       f.Evidence,
			Description:    f.Description,
			Recommendation: f.Recommendation,
			References:     f.References,
			DetectedAt:     f.DetectedAt,
		})
	}
	modules := make([]moduleCount, 0, len(moduleCounts))
	for name, count := range moduleCounts {
		modules = append(modules, moduleCount{name, count})
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Name < modules[j].Name })

	return htmlReportData{
		ScanID:      payload.ScanID,
		Target:      payload.Target,
		OWASP:       payload.OWASP,
		GeneratedAt: payload.FinishedAt,
		Stats:       payload.Stats,
		Modules:     modules,
		Findings:    findings,
	}
}

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VA Report &mdash; {{.ScanID}}</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.6}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
/* Header */
.header{background:#161b22;border-bottom:1px solid #30363d;padding:20px 32px}
.header-top{display:flex;align-items:center;gap:12px}
.header-icon{font-size:28px}
.header h1{font-size:20px;font-weight:700;color:#e6edf3}
.header-meta{color:#8b949e;font-size:12px;margin-top:8px;display:flex;flex-wrap:wrap;gap:16px}
.header-meta span{display:flex;align-items:center;gap:4px}
/* Container */
.container{max-width:1280px;margin:0 auto;padding:24px 32px}
/* Stat cards */
.stats-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}
.stat-card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px 12px;text-align:center;transition:transform .15s}
.stat-card:hover{transform:translateY(-2px)}
.stat-card.critical{border-color:#da3633;background:#1a0000}
.stat-card.high{border-color:#e3882b;background:#1a0d00}
.stat-card.medium{border-color:#d4ac0d;background:#1a1500}
.stat-card.low{border-color:#1f6feb;background:#001133}
.stat-card.neutral{border-color:#30363d}
.count{font-size:36px;font-weight:800;line-height:1.1}
.stat-card.critical .count{color:#da3633}
.stat-card.high .count{color:#e3882b}
.stat-card.medium .count{color:#d4ac0d}
.stat-card.low .count{color:#1f6feb}
.stat-card.neutral .count{color:#8b949e}
.stat-label{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#8b949e;margin-top:4px}
/* Section title */
.section-title{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:#8b949e;margin:24px 0 10px;padding-bottom:6px;border-bottom:1px solid #21262d}
/* Module pills */
.pill-row{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:24px}
.pill{background:#21262d;border:1px solid #30363d;border-radius:20px;padding:4px 14px;font-size:12px;color:#8b949e}
.pill strong{color:#e6edf3}
/* Toolbar */
.toolbar{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:16px}
.btn-group{display:flex;gap:6px}
.btn{background:#21262d;border:1px solid #30363d;border-radius:6px;color:#e6edf3;cursor:pointer;font-size:12px;padding:6px 16px;transition:background .15s,border-color .15s}
.btn:hover{background:#30363d}
.btn.active{background:#238636;border-color:#238636;color:#fff}
/* Summary table */
#summary-view table{width:100%;border-collapse:collapse}
#summary-view th{background:#161b22;border-bottom:2px solid #30363d;color:#8b949e;font-size:11px;font-weight:600;letter-spacing:.06em;padding:10px 14px;text-align:left;text-transform:uppercase;white-space:nowrap}
#summary-view td{border-bottom:1px solid #1c2128;padding:10px 14px;vertical-align:middle}
#summary-view tr:hover td{background:#161b22}
.url-cell{color:#58a6ff;font-family:monospace;font-size:11px;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
/* Severity badges */
.badge{border-radius:4px;display:inline-flex;align-items:center;font-size:10px;font-weight:700;letter-spacing:.05em;padding:2px 9px;text-transform:uppercase;white-space:nowrap}
.badge.critical{background:#3d0000;color:#ff6b6b;border:1px solid #da3633}
.badge.high{background:#3d1a00;color:#ffa94d;border:1px solid #e3882b}
.badge.medium{background:#3d3000;color:#ffd43b;border:1px solid #d4ac0d}
.badge.low{background:#002060;color:#74c0fc;border:1px solid #1f6feb}
/* Detailed view */
#detailed-view{display:none}
.finding-card{background:#161b22;border:1px solid #30363d;border-radius:10px;margin-bottom:10px;overflow:hidden}
.finding-card.critical{border-left:4px solid #da3633}
.finding-card.high{border-left:4px solid #e3882b}
.finding-card.medium{border-left:4px solid #d4ac0d}
.finding-card.low{border-left:4px solid #1f6feb}
.card-header{align-items:center;cursor:pointer;display:flex;justify-content:space-between;padding:14px 18px;user-select:none}
.card-header:hover{background:#1c2128}
.card-title-row{display:flex;align-items:center;gap:10px;font-weight:600;font-size:14px}
.card-subtitle{color:#8b949e;font-size:11px;margin-top:3px;display:flex;flex-wrap:wrap;gap:10px}
.card-subtitle span{display:flex;align-items:center;gap:3px}
.chevron{color:#8b949e;font-size:16px;font-weight:700;transition:transform .2s;flex-shrink:0}
.chevron.open{transform:rotate(180deg)}
.card-body{border-top:1px solid #30363d;display:none;padding:18px 20px}
.card-body.open{display:block}
.detail-grid{display:grid;gap:12px}
.detail-row{display:grid;grid-template-columns:140px 1fr;gap:8px;align-items:start}
.detail-label{color:#8b949e;font-size:12px;font-weight:600;padding-top:2px;text-transform:uppercase;letter-spacing:.04em}
.detail-value{color:#e6edf3;font-size:13px;word-break:break-word}
.evidence-box{background:#0d1117;border:1px solid #30363d;border-radius:6px;font-family:'Cascadia Code','Fira Code',Consolas,monospace;font-size:12px;padding:12px;white-space:pre-wrap;word-break:break-all;color:#79c0ff;margin-top:2px}
.refs-box{color:#58a6ff;font-size:12px;word-break:break-all}
/* CVSS pill */
.cvss-pill{background:#21262d;border:1px solid #30363d;border-radius:4px;font-size:11px;font-weight:700;padding:1px 7px;color:#e6edf3}
/* No findings */
.empty-state{text-align:center;padding:48px;color:#8b949e}
.empty-state .emoji{font-size:40px;margin-bottom:12px}
/* Responsive */
@media(max-width:900px){.stats-grid{grid-template-columns:repeat(3,1fr)}.container{padding:16px}.detail-row{grid-template-columns:1fr}}
@media(max-width:600px){.stats-grid{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <span class="header-icon">&#x1F6E1;</span>
    <h1>Vulnerability Assessment Report</h1>
  </div>
  <div class="header-meta">
    <span>&#x1F3AF; <strong>Target:</strong>&nbsp;{{.Target}}</span>
    <span>&#x1F194; <strong>Scan ID:</strong>&nbsp;{{.ScanID}}</span>
    <span>&#x1F4CB; <strong>Standard:</strong>&nbsp;{{.OWASP}}</span>
    {{if .GeneratedAt}}<span>&#x1F551; <strong>Generated:</strong>&nbsp;{{.GeneratedAt}}</span>{{end}}
  </div>
</div>

<div class="container">

  <!-- Severity Dashboard -->
  <div class="stats-grid">
    <div class="stat-card critical">
      <div class="count">{{.Stats.CriticalFindings}}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat-card high">
      <div class="count">{{.Stats.HighFindings}}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat-card medium">
      <div class="count">{{.Stats.MediumFindings}}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat-card low">
      <div class="count">{{.Stats.LowFindings}}</div>
      <div class="stat-label">Low</div>
    </div>
    <div class="stat-card neutral">
      <div class="count">{{.Stats.ScannedURLs}}</div>
      <div class="stat-label">URLs Scanned</div>
    </div>
  </div>

  <!-- Module Breakdown -->
  {{if .Modules}}
  <div class="section-title">Module Breakdown</div>
  <div class="pill-row">
    {{range .Modules}}
    <span class="pill">{{.Name}}: <strong>{{.Count}}</strong></span>
    {{end}}
  </div>
  {{end}}

  <!-- Findings -->
  <div class="section-title">Findings &mdash; {{.Stats.TotalFindings}} total</div>

  {{if eq .Stats.TotalFindings 0}}
  <div class="empty-state">
    <div class="emoji">&#x2705;</div>
    <div>No findings detected in this scan.</div>
  </div>
  {{else}}

  <div class="toolbar">
    <div class="btn-group">
      <button class="btn active" id="btn-summary" onclick="showView('summary')">Summary</button>
      <button class="btn" id="btn-detailed" onclick="showView('detailed')">Detailed</button>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="expandAll()">Expand All</button>
      <button class="btn" onclick="collapseAll()">Collapse All</button>
    </div>
  </div>

  <!-- Summary View -->
  <div id="summary-view">
    <table>
      <thead>
        <tr>
          <th>Module</th>
          <th>Title</th>
          <th>Severity</th>
          <th>CVSS</th>
          <th>URL</th>
        </tr>
      </thead>
      <tbody>
        {{range .Findings}}
        <tr>
          <td>{{.Module}}</td>
          <td>{{.Title}}</td>
          <td><span class="badge {{.SevClass}}">{{.Severity}}</span></td>
          <td><span class="cvss-pill">{{.CVSSScore}}</span></td>
          <td class="url-cell" title="{{.TargetURL}}">{{.TargetURL}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>

  <!-- Detailed View -->
  <div id="detailed-view">
    {{range .Findings}}
    <div class="finding-card {{.SevClass}}">
      <div class="card-header" onclick="toggleCard(this)">
        <div>
          <div class="card-title-row">
            <span class="badge {{.SevClass}}">{{.Severity}}</span>
            {{.Title}}
            <span class="cvss-pill">{{.CVSSScore}}</span>
          </div>
          <div class="card-subtitle">
            <span>&#x1F9E9; {{.Module}}</span>
            <span>&#x1F4CC; {{.OWASPCategory}}</span>
          </div>
        </div>
        <span class="chevron">&#x25BC;</span>
      </div>
      <div class="card-body">
        <div class="detail-grid">
          <div class="detail-row">
            <span class="detail-label">URL</span>
            <span class="detail-value"><a href="{{.TargetURL}}" target="_blank" rel="noopener">{{.TargetURL}}</a></span>
          </div>
          {{if .Description}}
          <div class="detail-row">
            <span class="detail-label">Description</span>
            <span class="detail-value">{{.Description}}</span>
          </div>
          {{end}}
          {{if .Evidence}}
          <div class="detail-row">
            <span class="detail-label">Evidence</span>
            <span class="detail-value"><div class="evidence-box">{{.Evidence}}</div></span>
          </div>
          {{end}}
          {{if .Recommendation}}
          <div class="detail-row">
            <span class="detail-label">Recommendation</span>
            <span class="detail-value">{{.Recommendation}}</span>
          </div>
          {{end}}
          {{if .References}}
          <div class="detail-row">
            <span class="detail-label">References</span>
            <span class="detail-value refs-box">{{.References}}</span>
          </div>
          {{end}}
          {{if .DetectedAt}}
          <div class="detail-row">
            <span class="detail-label">Detected At</span>
            <span class="detail-value" style="color:#8b949e;font-size:12px">{{.DetectedAt}}</span>
          </div>
          {{end}}
        </div>
      </div>
    </div>
    {{end}}
  </div>

  {{end}}
</div>

<script>
function showView(v){
  var s=document.getElementById('summary-view');
  var d=document.getElementById('detailed-view');
  var bs=document.getElementById('btn-summary');
  var bd=document.getElementById('btn-detailed');
  if(v==='summary'){s.style.display='';d.style.display='none';bs.classList.add('active');bd.classList.remove('active');}
  else{s.style.display='none';d.style.display='';bs.classList.remove('active');bd.classList.add('active');}
}
function toggleCard(header){
  var body=header.nextElementSibling;
  var chevron=header.querySelector('.chevron');
  var open=body.classList.contains('open');
  body.classList.toggle('open',!open);
  chevron.classList.toggle('open',!open);
}
function expandAll(){
  document.querySelectorAll('.card-body').forEach(function(b){b.classList.add('open');});
  document.querySelectorAll('.chevron').forEach(function(c){c.classList.add('open');});
}
function collapseAll(){
  document.querySelectorAll('.card-body').forEach(function(b){b.classList.remove('open');});
  document.querySelectorAll('.chevron').forEach(function(c){c.classList.remove('open');});
}
</script>
</body>
</html>`

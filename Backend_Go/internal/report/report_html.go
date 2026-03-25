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
	CWEIDs         string
	TargetURL      string
	Evidence       string
	Description    string
	Recommendation string
	References     string
	DetectedAt     string
	Request        string
	Response       string
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
			CWEIDs:         strings.Join(f.CWEIDs, ", "),
			TargetURL:      f.TargetURL,
			Evidence:       f.Evidence,
			Description:    f.Description,
			Recommendation: f.Recommendation,
			References:     f.References,
			DetectedAt:     f.DetectedAt,
			Request:        f.Request,
			Response:       f.Response,
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
/* ── Header ─────────────────────────────────────────── */
.header{background:#161b22;border-bottom:1px solid #30363d;padding:20px 32px}
.header-top{display:flex;align-items:center;gap:12px}
.header-icon{font-size:28px}
.header h1{font-size:20px;font-weight:700;color:#e6edf3}
.header-meta{color:#8b949e;font-size:12px;margin-top:8px;display:flex;flex-wrap:wrap;gap:16px}
.header-meta span{display:flex;align-items:center;gap:4px}
/* ── Container ──────────────────────────────────────── */
.container{max-width:1280px;margin:0 auto;padding:24px 32px}
/* ── Stat cards ─────────────────────────────────────── */
.stats-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}
.stat-card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px 12px;text-align:center;transition:transform .15s;cursor:pointer}
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
/* ── Section title ──────────────────────────────────── */
.section-title{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:#8b949e;margin:24px 0 10px;padding-bottom:6px;border-bottom:1px solid #21262d}
/* ── Module pills ───────────────────────────────────── */
.pill-row{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:24px}
.pill{background:#21262d;border:1px solid #30363d;border-radius:20px;padding:4px 14px;font-size:12px;color:#8b949e}
.pill strong{color:#e6edf3}
/* ── Buttons (base) ─────────────────────────────────── */
.btn-group{display:flex;gap:6px}
.btn{background:#21262d;border:1px solid #30363d;border-radius:6px;color:#e6edf3;cursor:pointer;font-size:12px;padding:6px 16px;transition:background .15s,border-color .15s,color .15s}
.btn:hover{background:#30363d}
.btn.active{background:#238636;border-color:#238636;color:#fff}
/* ── Severity filter bar ────────────────────────────── */
.filter-bar{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:14px;padding:10px 14px;background:#161b22;border:1px solid #30363d;border-radius:8px}
.filter-label{color:#8b949e;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;white-space:nowrap;margin-right:4px}
/* Severity-specific active colours for filter buttons */
.btn.sev-all.active{background:#238636;border-color:#238636;color:#fff}
.btn.sev-critical.active{background:#3d0000;border-color:#da3633;color:#ff6b6b}
.btn.sev-high.active{background:#3d1a00;border-color:#e3882b;color:#ffa94d}
.btn.sev-medium.active{background:#3d3000;border-color:#d4ac0d;color:#ffd43b}
.btn.sev-low.active{background:#002060;border-color:#1f6feb;color:#74c0fc}
/* ── Toolbar ────────────────────────────────────────── */
.toolbar{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:16px}
/* ── Summary table ──────────────────────────────────── */
#summary-view table{width:100%;border-collapse:collapse}
#summary-view th{background:#161b22;border-bottom:2px solid #30363d;color:#8b949e;font-size:11px;font-weight:600;letter-spacing:.06em;padding:10px 14px;text-align:left;text-transform:uppercase;white-space:nowrap}
#summary-view td{border-bottom:1px solid #1c2128;padding:10px 14px;vertical-align:middle}
#summary-view tr.finding-row:hover td{background:#161b22}
.url-cell{color:#58a6ff;font-family:monospace;font-size:11px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
/* ── Severity badges ────────────────────────────────── */
.badge{border-radius:4px;display:inline-flex;align-items:center;font-size:10px;font-weight:700;letter-spacing:.05em;padding:2px 9px;text-transform:uppercase;white-space:nowrap}
.badge.critical{background:#3d0000;color:#ff6b6b;border:1px solid #da3633}
.badge.high{background:#3d1a00;color:#ffa94d;border:1px solid #e3882b}
.badge.medium{background:#3d3000;color:#ffd43b;border:1px solid #d4ac0d}
.badge.low{background:#002060;color:#74c0fc;border:1px solid #1f6feb}
/* ── Detail button & inline expand row ──────────────── */
.btn-detail{padding:4px 11px;font-size:11px}
.btn-detail.open{background:rgba(56,139,253,.15);border-color:#388bfd;color:#58a6ff}
.detail-exp-row{display:none}
.detail-exp-row>td{padding:0;border-bottom:2px solid rgba(56,139,253,.2)}
.detail-exp-cell{background:#0d1117;border-left:3px solid #388bfd;padding:16px 24px}
/* ── Shared detail content ──────────────────────────── */
.detail-grid{display:grid;gap:12px}
.detail-row{display:grid;grid-template-columns:140px 1fr;gap:8px;align-items:start}
.detail-label{color:#8b949e;font-size:12px;font-weight:600;padding-top:2px;text-transform:uppercase;letter-spacing:.04em}
.detail-value{color:#e6edf3;font-size:13px;word-break:break-word}
.evidence-box{background:#0d1117;border:1px solid #30363d;border-radius:6px;font-family:'Cascadia Code','Fira Code',Consolas,monospace;font-size:12px;padding:12px;white-space:pre-wrap;word-break:break-all;color:#79c0ff;margin-top:2px}
.refs-box{color:#58a6ff;font-size:12px;word-break:break-all}
/* ── CVSS pill ──────────────────────────────────────── */
.cvss-pill{background:#21262d;border:1px solid #30363d;border-radius:4px;font-size:11px;font-weight:700;padding:1px 7px;color:#e6edf3}
/* ── Empty state ────────────────────────────────────── */
.empty-state{text-align:center;padding:48px;color:#8b949e}
.empty-state .emoji{font-size:40px;margin-bottom:12px}
/* ── Responsive ─────────────────────────────────────── */
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

  <!-- Severity Dashboard (clicking a card also filters) -->
  <div class="stats-grid">
    <div class="stat-card critical" onclick="toggleSev('critical')" title="Click to filter Critical">
      <div class="count">{{.Stats.CriticalFindings}}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat-card high" onclick="toggleSev('high')" title="Click to filter High">
      <div class="count">{{.Stats.HighFindings}}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat-card medium" onclick="toggleSev('medium')" title="Click to filter Medium">
      <div class="count">{{.Stats.MediumFindings}}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat-card low" onclick="toggleSev('low')" title="Click to filter Low">
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

  <!-- Severity Filter Bar (multi-select) -->
  <div class="filter-bar">
    <span class="filter-label">Filter:</span>
    <div class="btn-group">
      <button class="btn sev-all active" id="fsev-all"      onclick="toggleSev('all')">All</button>
      <button class="btn sev-critical"   id="fsev-critical" onclick="toggleSev('critical')">&#9632; Critical</button>
      <button class="btn sev-high"       id="fsev-high"     onclick="toggleSev('high')">&#9632; High</button>
      <button class="btn sev-medium"     id="fsev-medium"   onclick="toggleSev('medium')">&#9632; Medium</button>
      <button class="btn sev-low"        id="fsev-low"      onclick="toggleSev('low')">&#9632; Low</button>
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
          <th>CWE</th>
          <th>URL</th>
          <th style="text-align:center">Detail</th>
        </tr>
      </thead>
      <tbody>
        {{range .Findings}}
        <tr class="finding-row" data-sev="{{.SevClass}}">
          <td>{{.Module}}</td>
          <td>{{.Title}}</td>
          <td><span class="badge {{.SevClass}}">{{.Severity}}</span></td>
          <td><span class="cvss-pill">{{.CVSSScore}}</span></td>
          <td style="font-size:11px;color:#8b949e;font-family:monospace">{{if .CWEIDs}}{{.CWEIDs}}{{else}}&mdash;{{end}}</td>
          <td class="url-cell" title="{{.TargetURL}}">{{.TargetURL}}</td>
          <td style="text-align:center;white-space:nowrap">
            <button class="btn btn-detail" onclick="toggleDetail(this)">Detail &#x25BE;</button>
          </td>
        </tr>
        <!-- Inline detail expand row (hidden by default, toggled by Detail button) -->
        <tr class="detail-exp-row">
          <td colspan="7">
            <div class="detail-exp-cell">
              <div class="detail-grid">
                <div class="detail-row">
                  <span class="detail-label">Severity</span>
                  <span class="detail-value">
                    <span class="badge {{.SevClass}}">{{.Severity}}</span>
                    &nbsp;<span class="cvss-pill">CVSS&nbsp;{{.CVSSScore}}</span>
                  </span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">OWASP</span>
                  <span class="detail-value" style="font-size:12px">{{.OWASPCategory}}</span>
                </div>
                {{if .CWEIDs}}
                <div class="detail-row">
                  <span class="detail-label">CWE</span>
                  <span class="detail-value" style="font-family:monospace;color:#79c0ff">{{.CWEIDs}}</span>
                </div>
                {{end}}
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
                {{if .Request}}
                <div class="detail-row">
                  <span class="detail-label">Request</span>
                  <span class="detail-value"><div class="evidence-box">{{.Request}}</div></span>
                </div>
                {{end}}
                {{if .Response}}
                <div class="detail-row">
                  <span class="detail-label">Response</span>
                  <span class="detail-value"><div class="evidence-box">{{.Response}}</div></span>
                </div>
                {{end}}
              </div>
            </div>
          </td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>

  {{end}}
</div>

<script>
// ── Severity filter (multi-select) ────────────────────────────────────────────
// activeSevs tracks which severities are selected.
// 'all' = show everything; selecting individual severities replaces 'all'.
var activeSevs = new Set(['all']);

function toggleSev(sev) {
  if (sev === 'all') {
    // Reset to "show all"
    activeSevs = new Set(['all']);
  } else {
    activeSevs.delete('all');
    if (activeSevs.has(sev)) {
      activeSevs.delete(sev);
      if (activeSevs.size === 0) activeSevs.add('all'); // nothing selected → revert to All
    } else {
      activeSevs.add(sev);
    }
  }
  syncFilterBtns();
  applyFilter();
}

function syncFilterBtns() {
  ['all', 'critical', 'high', 'medium', 'low'].forEach(function(s) {
    var btn = document.getElementById('fsev-' + s);
    if (btn) btn.classList.toggle('active', activeSevs.has(s));
  });
}

function applyFilter() {
  var showAll = activeSevs.has('all');

  // Summary table: toggle finding-row visibility and close their inline detail rows
  document.querySelectorAll('#summary-view .finding-row').forEach(function(row) {
    var visible = showAll || activeSevs.has(row.dataset.sev);
    row.style.display = visible ? '' : 'none';
    var detailRow = row.nextElementSibling; // always the .detail-exp-row
    if (detailRow && detailRow.classList.contains('detail-exp-row')) {
      if (!visible) {
        // Collapse detail row and reset button when parent is hidden
        detailRow.style.display = 'none';
        var btn = row.querySelector('.btn-detail');
        if (btn) { btn.classList.remove('open'); btn.innerHTML = 'Detail &#x25BE;'; }
      }
      // If visible, leave detail row in its current open/closed state
    }
  });

}

// ── Inline detail toggle in summary row ───────────────────────────────────────
function toggleDetail(btn) {
  var tr = btn.closest('tr');
  var detailRow = tr.nextElementSibling; // the .detail-exp-row immediately below
  var open = detailRow.style.display !== 'none' && detailRow.style.display !== '';
  if (open) {
    detailRow.style.display = 'none';
    btn.classList.remove('open');
    btn.innerHTML = 'Detail &#x25BE;';
  } else {
    detailRow.style.display = 'table-row';
    btn.classList.add('open');
    btn.innerHTML = 'Detail &#x25B4;';
  }
}

</script>
</body>
</html>`

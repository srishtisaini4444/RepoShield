import { useState } from 'react'
import {
  ShieldCheck, Search, GitBranch, Activity, Package, AlertTriangle,
  CheckCircle2, XCircle, Clock3, ArrowUpRight, ShieldAlert,
  RefreshCw, ChevronDown, ExternalLink, Terminal, LockKeyhole,
  FileSearch, Info
} from 'lucide-react'
import './App.css'

const initialScan = {
  status: 'idle',
  data: null,
  error: '',
}

function severityClass(severity = 'unknown') {
  const value = String(severity).toLowerCase()
  if (value === 'critical') return 'critical'
  if (value === 'high') return 'high'
  if (value === 'medium') return 'medium'
  if (value === 'low') return 'low'
  return 'unknown'
}

function prettyStatus(status) {
  if (status === 'completed') return 'Completed'
  if (status === 'partial') return 'Partially completed'
  return 'Unknown'
}

function formatLabel(value = '') {
  return String(value)
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function App() {
  const [packageName, setPackageName] = useState('')
  const [version, setVersion] = useState('')
  const [scan, setScan] = useState(initialScan)
  const [activeTab, setActiveTab] = useState('all')
  const [showDetails, setShowDetails] = useState(false)

  const result = scan.data
  const findings = result?.findings ?? []
  const filteredFindings = findings.filter((finding) => {
    if (activeTab === 'all') return true
    return String(finding.severity).toLowerCase() === activeTab
  })

  const counts = {
    critical: findings.filter((item) => String(item.severity).toLowerCase() === 'critical').length,
    high: findings.filter((item) => String(item.severity).toLowerCase() === 'high').length,
    medium: findings.filter((item) => String(item.severity).toLowerCase() === 'medium').length,
    low: findings.filter((item) => String(item.severity).toLowerCase() === 'low').length,
  }

  async function handleScan(event) {
    event.preventDefault()

    const cleanName = packageName.trim()
    const cleanVersion = version.trim()

    if (!cleanName) {
      setScan({ status: 'error', data: null, error: 'Enter an npm package name to start scanning.' })
      return
    }

    setScan({ status: 'loading', data: null, error: '' })
    setActiveTab('all')
    setShowDetails(false)

    const controller = new AbortController()
    const timeoutId = window.setTimeout(() => controller.abort(), 20000)

    try {
      const payload = { package_name: cleanName }
      if (cleanVersion) payload.version = cleanVersion

      const response = await fetch(`${import.meta.env.VITE_API_BASE_URL || ""}/api/v1/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      })

      const body = await response.json().catch(() => ({}))

      if (!response.ok) {
        const message = typeof body.detail === 'string'
          ? body.detail
          : 'The scan could not be completed. Check the package name and try again.'
        throw new Error(message)
      }

      setScan({ status: 'success', data: body, error: '' })
    } catch (error) {
      const message = error.name === 'AbortError'
        ? 'The scan took too long. The upstream service may be slow. Please try again.'
        : error.message || 'Unable to reach RepoShield. Check that the backend is running.'
      setScan({ status: 'error', data: null, error: message })
    } finally {
      window.clearTimeout(timeoutId)
    }
  }

  const riskLevel = result?.risk_level || 'unknown'
  const riskText = riskLevel === 'no_findings'
    ? 'No findings'
    : formatLabel(riskLevel)

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#" aria-label="RepoShield home">
          <span className="brand-icon"><ShieldCheck size={23} /></span>
          <span className="brand-copy">
            <strong>RepoShield</strong>
            <small>SUPPLY CHAIN SECURITY</small>
          </span>
        </a>

        <div className="workspace-label">WORKSPACE</div>
        <button className="nav-item active" type="button">
          <Activity size={18} /> Overview
        </button>
        <button
          className="nav-item"
          type="button"
          onClick={() => document.getElementById('scanner')?.scrollIntoView({ behavior: 'smooth' })}
        >
          <Search size={18} /> Package scanner
        </button>
        <button
          className="nav-item"
          type="button"
          onClick={() => result && document.getElementById('findings')?.scrollIntoView({ behavior: 'smooth' })}
        >
          <ShieldAlert size={18} /> Findings
          {findings.length > 0 && <span className="nav-count">{findings.length}</span>}
        </button>

        <div className="sidebar-divider" />

        <div className="workspace-label">PROJECT</div>
        <div className="project-card">
          <span className="project-icon"><Terminal size={17} /></span>
          <span><strong>RepoShield Core</strong><small>Level 1 assessment</small></span>
          <span className="online-dot" />
        </div>

        <div className="sidebar-bottom">
          <div className="sidebar-security">
            <LockKeyhole size={17} />
            <div><strong>Security first</strong><p>Packages are inspected, never executed.</p></div>
          </div>
          <div className="sidebar-version">
            <span className="status-dot" /> API connection uses local proxy
            <span>v1.0.0</span>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">Workspace <span>/</span> <strong>Overview</strong></div>
          <div className="topbar-right">
            <span className="environment"><span className="status-dot" /> Development</span>
            <div className="avatar">RS</div>
          </div>
        </header>

        <div className="page-content">
          <section className="welcome-row">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" /> OPEN-SOURCE SECURITY INTELLIGENCE</div>
              <h1>Know what you're <span>installing.</span></h1>
              <p className="subtitle">
                Inspect npm packages for known vulnerabilities and suspicious configuration signals.
                Evidence first. No false promises.
              </p>
            </div>
            <div className="shield-art" aria-hidden="true">
              <div className="shield-orbit orbit-one" />
              <div className="shield-orbit orbit-two" />
              <div className="shield-glow"><ShieldCheck size={49} strokeWidth={1.3} /></div>
              <span className="orbit-dot dot-one" /><span className="orbit-dot dot-two" />
            </div>
          </section>

          <section className="stats-grid" aria-label="Current scan summary">
            <article className="stat-card">
              <div className="stat-top"><span>Scan status</span><Activity size={17} /></div>
              <strong className="stat-value">{result ? prettyStatus(result.status) : 'Ready to scan'}</strong>
              <span className="stat-foot"><span className="status-dot" /> {result ? 'Latest scan' : 'Waiting for package'}</span>
            </article>
            <article className="stat-card">
              <div className="stat-top"><span>Findings detected</span><AlertTriangle size={17} /></div>
              <strong className="stat-value">{result ? result.findings_count ?? findings.length : '—'}</strong>
              <span className="stat-foot">Evidence-backed signals</span>
            </article>
            <article className="stat-card">
              <div className="stat-top"><span>Risk assessment</span><ShieldAlert size={17} /></div>
              <strong className={`stat-value risk-${severityClass(riskLevel)}`}>
                {result ? riskText : 'Not assessed'}
              </strong>
              <span className="stat-foot">Based on available checks</span>
            </article>
            <article className="stat-card">
              <div className="stat-top"><span>Checks reported</span><FileSearch size={17} /></div>
              <strong className="stat-value">{result ? (result.checks || []).length : '—'}</strong>
              <span className="stat-foot">Completed and failed checks</span>
            </article>
          </section>

          <section className="scanner-panel panel" id="scanner">
            <div className="panel-heading">
              <div className="heading-icon"><Search size={19} /></div>
              <div><h2>Package scanner</h2><p>Start with a package name. A version is optional.</p></div>
              <span className="api-badge"><span className="status-dot" /> API scan</span>
            </div>

            <form className="scan-form" onSubmit={handleScan}>
              <label className="input-group package-input">
                <span>PACKAGE NAME</span>
                <div className="input-wrap">
                  <Package size={18} />
                  <input
                    value={packageName}
                    onChange={(event) => setPackageName(event.target.value)}
                    placeholder="e.g. express, lodash, @types/node"
                    maxLength={214}
                    autoComplete="off"
                    spellCheck="false"
                    aria-label="npm package name"
                  />
                </div>
              </label>
              <label className="input-group version-input">
                <span>VERSION <small>OPTIONAL</small></span>
                <div className="input-wrap">
                  <span className="version-prefix">@</span>
                  <input
                    value={version}
                    onChange={(event) => setVersion(event.target.value)}
                    placeholder="latest"
                    maxLength={100}
                    autoComplete="off"
                    spellCheck="false"
                    aria-label="Package version"
                  />
                  <ChevronDown size={16} className="muted-icon" />
                </div>
              </label>
              <button className="scan-button" type="submit" disabled={scan.status === 'loading'}>
                {scan.status === 'loading'
                  ? <><RefreshCw className="spin" size={17} /> Scanning...</>
                  : <><Search size={17} /> Scan package <ArrowUpRight size={16} /></>}
              </button>
            </form>

            <div className="scanner-footer">
              <span><LockKeyhole size={14} /> Read-only inspection</span>
              <span><Clock3 size={14} /> Usually a few seconds</span>
              <span><CheckCircle2 size={14} /> No package execution</span>
            </div>

            {scan.status === 'loading' && (
              <div className="loading-box" role="status">
                <div className="loading-spinner"><RefreshCw size={22} className="spin" /></div>
                <div><strong>Inspecting package signals</strong><p>Retrieving registry metadata and checking available security signals...</p></div>
              </div>
            )}

            {scan.status === 'error' && (
              <div className="error-box" role="alert">
                <XCircle size={20} />
                <div><strong>Scan couldn't be completed</strong><p>{scan.error}</p></div>
              </div>
            )}
          </section>

          {result ? (
            <>
              <section className="result-heading">
                <div>
                  <div className="eyebrow">SCAN REPORT</div>
                  <h2>Results for <span>{result.target?.package_name || packageName}</span></h2>
                  <p>
                    Resolved version: <strong>{result.target?.resolved_version || result.package?.version || 'Unknown'}</strong>
                    {result.target?.requested_version && <> · Requested: <strong>{result.target.requested_version}</strong></>}
                  </p>
                </div>
                <span className={`report-status ${result.status === 'completed' ? 'status-complete' : 'status-partial'}`}>
                  {result.status === 'completed' ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}
                  {prettyStatus(result.status)}
                </span>
              </section>

              {result.status !== 'completed' && (
                <div className="warning-banner">
                  <AlertTriangle size={19} />
                  <div><strong>This report is incomplete</strong><p>One or more checks failed. Missing results must not be interpreted as evidence of safety.</p></div>
                </div>
              )}

              <section className="report-grid">
                <article className="panel package-card">
                  <div className="package-card-top">
                    <div className="package-large-icon"><Package size={23} /></div>
                    <span className="package-source"><GitBranch size={14} /> npm registry</span>
                  </div>
                  <h3>{result.package?.name || result.target?.package_name}</h3>
                  <p className="package-description">{result.package?.description || 'No package description was provided by the registry.'}</p>
                  <div className="package-meta">
                    <div><span>VERSION</span><strong>{result.package?.version || result.target?.resolved_version || 'Unknown'}</strong></div>
                    <div><span>FINDINGS</span><strong>{findings.length}</strong></div>
                  </div>
                  <div className={`risk-summary risk-border-${severityClass(riskLevel)}`}>
                    <span className="risk-summary-icon"><ShieldAlert size={19} /></span>
                    <div><small>OVERALL ASSESSMENT</small><strong>{riskText}</strong></div>
                  </div>
                  <p className="assessment-note"><Info size={14} /> This is a limited assessment, not a guarantee that the package is safe.</p>
                </article>

                <article className="panel checks-card">
                  <div className="section-title-row"><div><h3>Security checks</h3><p>What RepoShield was able to inspect</p></div><span className="count-pill">{(result.checks || []).length} checks</span></div>
                  <div className="check-list">
                    {(result.checks || []).map((check, index) => {
                      const passed = check.status === 'completed'
                      return (
                        <div className="check-row" key={`${check.check_id || check.name || 'check'}-${index}`}>
                          <span className={`check-icon ${passed ? 'check-pass' : 'check-fail'}`}>
                            {passed ? <CheckCircle2 size={17} /> : <XCircle size={17} />}
                          </span>
                          <div className="check-copy">
                            <strong>{formatLabel(check.check_id || check.name || 'Security check')}</strong>
                            <p>{check.message || (passed ? 'Check completed.' : 'Check could not complete.')}</p>
                          </div>
                          <span className={`check-state ${passed ? 'text-success' : 'text-danger'}`}>{passed ? 'Done' : 'Failed'}</span>
                        </div>
                      )
                    })}
                  </div>
                  <button className="details-toggle" type="button" onClick={() => setShowDetails(!showDetails)}>
                    {showDetails ? 'Hide technical details' : 'View technical details'}
                    <ChevronDown size={16} className={showDetails ? 'rotate-up' : ''} />
                  </button>
                  {showDetails && (
                    <pre className="technical-details">{JSON.stringify({
                      target: result.target,
                      status: result.status,
                      risk_level: result.risk_level,
                      findings_count: result.findings_count,
                    }, null, 2)}</pre>
                  )}
                </article>
              </section>

              <section className="panel findings-panel" id="findings">
                <div className="section-title-row findings-header">
                  <div><div className="eyebrow">EVIDENCE & EXPLANATIONS</div><h2>Security findings <span className="count-pill">{findings.length}</span></h2><p>Review each signal and its recommended next step.</p></div>
                  <div className="finding-summary">
                    <span className="summary-high">{counts.critical + counts.high} high+</span>
                    <span className="summary-medium">{counts.medium} medium</span>
                    <span className="summary-low">{counts.low} low</span>
                  </div>
                </div>

                <div className="filter-tabs" role="tablist" aria-label="Filter findings">
                  {['all', 'critical', 'high', 'medium', 'low'].map((tab) => (
                    <button
                      key={tab}
                      type="button"
                      role="tab"
                      aria-selected={activeTab === tab}
                      className={activeTab === tab ? 'filter-tab selected' : 'filter-tab'}
                      onClick={() => setActiveTab(tab)}
                    >
                      {formatLabel(tab)}
                      {tab === 'all' && <span>{findings.length}</span>}
                    </button>
                  ))}
                </div>

                {filteredFindings.length > 0 ? (
                  <div className="finding-list">
                    {filteredFindings.map((finding, index) => (
                      <article className="finding-item" key={`${finding.id || finding.rule_id || 'finding'}-${index}`}>
                        <div className={`severity-marker ${severityClass(finding.severity)}`} />
                        <div className="finding-main">
                          <div className="finding-title-row">
                            <span className={`severity-badge ${severityClass(finding.severity)}`}>{formatLabel(finding.severity || 'unknown')}</span>
                            <span className="finding-id">{finding.id || finding.rule_id || 'Finding'}</span>
                            <span className="finding-source">{formatLabel(finding.source || 'unknown source')}</span>
                          </div>
                          <h3>{finding.title || 'Security signal detected'}</h3>
                          <p>{finding.description || finding.summary || 'No additional description was supplied.'}</p>
                          {finding.evidence && (
                            <div className="evidence-box">
                              <span><FileSearch size={14} /> EVIDENCE</span>
                              <pre>{typeof finding.evidence === 'string' ? finding.evidence : JSON.stringify(finding.evidence, null, 2)}</pre>
                            </div>
                          )}
                          {finding.recommendation && (
                            <div className="recommendation"><CheckCircle2 size={16} /><div><strong>Recommended action</strong><p>{finding.recommendation}</p></div></div>
                          )}
                          {Array.isArray(finding.references) && finding.references.length > 0 && (
                            <div className="reference-links">
                              {finding.references.slice(0, 5).map((reference, refIndex) => {
                                const url = typeof reference === 'string' ? reference : reference?.url
                                if (!url) return null
                                try {
                                  const parsed = new URL(url)
                                  if (!['https:', 'http:'].includes(parsed.protocol)) return null
                                  return <a key={`${url}-${refIndex}`} href={parsed.href} target="_blank" rel="noreferrer noopener">Advisory reference <ExternalLink size={12} /></a>
                                } catch {
                                  return null
                                }
                              })}
                            </div>
                          )}
                        </div>
                      </article>
                    ))}
                  </div>
                ) : (
                  <div className="empty-findings">
                    <div className="empty-icon"><ShieldCheck size={28} /></div>
                    <h3>{findings.length === 0 ? 'No findings returned' : 'No findings in this category'}</h3>
                    <p>{findings.length === 0
                      ? 'The completed checks returned no findings. This does not prove the package is safe.'
                      : 'Try a different severity filter to see other findings.'}</p>
                  </div>
                )}

                {Array.isArray(result.limitations) && result.limitations.length > 0 && (
                  <div className="limitations-box">
                    <Info size={17} />
                    <div><strong>Assessment limitations</strong><ul>{result.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></div>
                  </div>
                )}
              </section>
            </>
          ) : (
            <section className="empty-state panel">
              <div className="empty-illustration"><div className="empty-ring"><ShieldCheck size={38} /></div><span className="empty-spark spark-a" /><span className="empty-spark spark-b" /></div>
              <h2>Your next scan starts here</h2>
              <p>Enter an npm package above to inspect its available security signals. Try a familiar package to see how the report works.</p>
              <div className="suggestion-label">QUICK START</div>
              <div className="suggestions">
                {['express', 'lodash', '@types/node'].map((name) => (
                  <button key={name} type="button" onClick={() => setPackageName(name)}><Package size={15} /> {name} <ArrowUpRight size={13} /></button>
                ))}
              </div>
            </section>
          )}

          <footer className="page-footer">
            <div className="footer-brand"><ShieldCheck size={17} /> RepoShield <span>·</span> Explainable supply-chain risk assessment</div>
            <div>Built for transparency, not false certainty.</div>
          </footer>
        </div>
      </main>
    </div>
  )
}

export default App
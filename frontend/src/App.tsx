
import './App.css'
import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowDownToLine, ArrowUpRight,
  BarChart3, Bell, CheckCircle2, ChevronRight, Clock3,
  FileSearch, FileText, FolderOpen, LayoutDashboard, Loader2,
  LockKeyhole, Menu, RefreshCw, Search, Shield, ShieldCheck,
  UploadCloud, X, Zap,
} from 'lucide-react'
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from 'recharts'

const API = 'http://127.0.0.1:8000/api'

type Finding = {
  rule_id: string
  title: string
  severity: string
  confidence: string
  host: string
  username?: string
  source_ip?: string
  first_seen: string
  description: string
  evidence: Array<Record<string, unknown>>
  recommendations?: string[]
}

type Investigation = {
  id: string
  created_at: string
  source_file: string
  event_count: number
  rejected_count: number
  finding_count: number
  findings?: Finding[]
}

type SecurityEvent = {
  timestamp: string
  event_id: string
  source: string
  host: string
  event_type: string
  severity: string
  username?: string
  source_ip?: string
  logon_type?: string
  session_id?: string
  session_address?: string
  destination_ip?: string
  process_name?: string
  command_line?: string
  message?: string
  fingerprint?: string
  raw?: Record<string, unknown>
}

type EventResponse = {
  total: number
  page: number
  page_size: number
  total_pages: number
  events: SecurityEvent[]
}

type Page =
  | 'Overview'
  | 'Investigations'
  | 'Log Ingestion'
  | 'Event Explorer'
  | 'Evidence Timeline'
  | 'Reports'

const navigation: Array<{ name: Page; icon: typeof LayoutDashboard }> = [
  { name: 'Overview', icon: LayoutDashboard },
  { name: 'Investigations', icon: FileSearch },
  { name: 'Log Ingestion', icon: UploadCloud },
  { name: 'Event Explorer', icon: Search },
  { name: 'Evidence Timeline', icon: Clock3 },
  { name: 'Reports', icon: FileText },
]

function App() {
  const [page, setPage] = useState<Page>('Overview')
  const [investigations, setInvestigations] = useState<Investigation[]>([])
  const [selected, setSelected] = useState<Investigation | null>(null)
  const [loading, setLoading] = useState(true)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [search, setSearch] = useState('')
  const [mobileMenu, setMobileMenu] = useState(false)

  // Event Explorer and Evidence Timeline state
  const [activeInvestigation, setActiveInvestigation] = useState('')
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [timeline, setTimeline] = useState<SecurityEvent[]>([])
  const [eventTotal, setEventTotal] = useState(0)
  const [eventPage, setEventPage] = useState(1)
  const [eventPages, setEventPages] = useState(1)
  const [eventSearch, setEventSearch] = useState('')
  const [eventIdFilter, setEventIdFilter] = useState('')
  const [hostFilter, setHostFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [usernameFilter, setUsernameFilter] = useState('')
  const [eventLoading, setEventLoading] = useState(false)
  const [inspectedEvent, setInspectedEvent] = useState<SecurityEvent | null>(null)

  const loadInvestigations = useCallback(async () => {
    setLoading(true)
    setError('')

    try {
      const response = await fetch(`${API}/investigations`)
      if (!response.ok) throw new Error(`API returned ${response.status}`)

      const data = await response.json()
      const summaries: Investigation[] = data.investigations ?? []

      const details = await Promise.all(
        summaries.map(async (item) => {
          try {
            const result = await fetch(`${API}/investigations/${item.id}`)
            if (!result.ok) return item
            return await result.json() as Investigation
          } catch {
            return item
          }
        }),
      )

      setInvestigations(details)
    } catch {
      setError('Cannot connect to SentinelTrace API. Make sure the FastAPI server is running on port 8000.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadInvestigations()
  }, [loadInvestigations])

  useEffect(() => {
    if (investigations.length && !activeInvestigation) {
      setActiveInvestigation(investigations[0].id)
    }
  }, [investigations, activeInvestigation])

  const totals = useMemo(() => {
    const findings = investigations.flatMap((item) => item.findings ?? [])
    return {
      events: investigations.reduce((sum, item) => sum + item.event_count, 0),
      findings: findings.length,
      investigations: investigations.length,
      rejected: investigations.reduce((sum, item) => sum + item.rejected_count, 0),
      high: findings.filter((item) =>
        ['high', 'critical'].includes(item.severity.toLowerCase()),
      ).length,
      medium: findings.filter((item) => item.severity.toLowerCase() === 'medium').length,
      low: findings.filter((item) => item.severity.toLowerCase() === 'low').length,
    }
  }, [investigations])

  const filtered = investigations.filter((item) =>
    `${item.source_file} ${item.id}`.toLowerCase().includes(search.toLowerCase()),
  )

  async function uploadFile(file?: File) {
    if (!file) return

    setUploading(true)
    setError('')
    setSuccess('')

    try {
      const form = new FormData()
      form.append('file', file)

      const response = await fetch(`${API}/investigations`, {
        method: 'POST',
        body: form,
      })

      const data = await response.json()
      if (!response.ok) {
        throw new Error(data.detail ?? `Upload failed (${response.status})`)
      }

      setSuccess(
        `Investigation completed: ${data.event_count} events processed, ${data.finding_count} findings generated.`,
      )

      await loadInvestigations()
      setPage('Investigations')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed.')
    } finally {
      setUploading(false)
    }
  }

  async function downloadReport(item: Investigation) {
    try {
      const response = await fetch(`${API}/investigations/${item.id}/report`)
      if (!response.ok) throw new Error(`Report API returned ${response.status}`)

      const data = await response.json()
      downloadBlob(
        new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }),
        `sentineltrace-${item.id}.json`,
      )
    } catch (err) {
      setError(err instanceof Error ? err.message : 'JSON report download failed.')
    }
  }

  async function downloadMarkdown(item: Investigation) {
    try {
      const response = await fetch(
        `${API}/investigations/${item.id}/report/markdown`,
      )

      if (!response.ok) {
        throw new Error(`Markdown report API returned ${response.status}`)
      }

      const blob = await response.blob()
      downloadBlob(blob, `sentineltrace-${item.id}.md`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Markdown report download failed.')
    }
  }

  function downloadBlob(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
  }

  async function loadEvents() {
    if (!activeInvestigation) return

    setEventLoading(true)
    setError('')

    try {
      const params = new URLSearchParams({
        page: String(eventPage),
        page_size: '50',
      })

      if (eventSearch) params.set('search', eventSearch)
      if (eventIdFilter) params.set('event_id', eventIdFilter)
      if (hostFilter) params.set('host', hostFilter)
      if (severityFilter) params.set('severity', severityFilter)
      if (usernameFilter) params.set('username', usernameFilter)

      const response = await fetch(
        `${API}/investigations/${activeInvestigation}/events?${params}`,
      )

      if (!response.ok) {
        throw new Error(`Events API returned ${response.status}`)
      }

      const data: EventResponse = await response.json()
      setEvents(data.events ?? [])
      setEventTotal(data.total ?? 0)
      setEventPages(data.total_pages ?? 1)
    } catch (err) {
      setEvents([])
      setError(err instanceof Error ? err.message : 'Unable to load events.')
    } finally {
      setEventLoading(false)
    }
  }

  async function loadTimeline() {
    if (!activeInvestigation) return

    setEventLoading(true)
    setError('')

    try {
      const response = await fetch(
        `${API}/investigations/${activeInvestigation}/timeline?limit=500`,
      )

      if (!response.ok) {
        throw new Error(`Timeline API returned ${response.status}`)
      }

      const data = await response.json()
      setTimeline(data.timeline ?? [])
    } catch (err) {
      setTimeline([])
      setError(err instanceof Error ? err.message : 'Unable to load timeline.')
    } finally {
      setEventLoading(false)
    }
  }

  useEffect(() => {
    if (page === 'Event Explorer') {
      void loadEvents()
    }
  }, [
    page,
    activeInvestigation,
    eventPage,
    eventSearch,
    eventIdFilter,
    hostFilter,
    severityFilter,
    usernameFilter,
  ])

  useEffect(() => {
    if (page === 'Evidence Timeline') {
      void loadTimeline()
    }
  }, [page, activeInvestigation])

  const chartData = useMemo(() => {
    const buckets = new Map<string, number>()

    investigations.forEach((item) => {
      const day = new Date(item.created_at).toLocaleDateString()
      buckets.set(day, (buckets.get(day) ?? 0) + item.event_count)
    })

    return Array.from(buckets, ([date, events]) => ({ date, events })).slice(-7)
  }, [investigations])

  const content = (
    <>
      {error && (
        <div className="notice error-notice">
          <AlertTriangle size={17} />
          <span>{error}</span>
          <button onClick={() => setError('')} aria-label="Dismiss">
            <X size={16} />
          </button>
        </div>
      )}

      {success && (
        <div className="notice success-notice">
          <CheckCircle2 size={17} />
          <span>{success}</span>
          <button onClick={() => setSuccess('')} aria-label="Dismiss">
            <X size={16} />
          </button>
        </div>
      )}

      {page === 'Overview' && (
        <>
          <div className="page-heading">
            <div>
              <div className="eyebrow">SECURITY OPERATIONS / OVERVIEW</div>
              <h1>Security Overview</h1>
              <p>Evidence-based visibility into your security investigations.</p>
            </div>
            <button className="button secondary" onClick={() => void loadInvestigations()}>
              <RefreshCw size={15} /> Refresh data
            </button>
          </div>

          <div className="metric-grid">
            <Metric icon={Activity} label="Events Processed" value={totals.events.toLocaleString()} note="Across saved investigations" />
            <Metric icon={FolderOpen} label="Investigations" value={totals.investigations.toString()} note="Saved analysis runs" />
            <Metric icon={AlertTriangle} label="Detection Findings" value={totals.findings.toString()} note="Analyst review required" />
            <Metric icon={ShieldCheck} label="Rejected Records" value={totals.rejected.toString()} note="Parser validation errors" />
          </div>

          <div className="dashboard-grid">
            <section className="panel chart-panel">
              <div className="panel-heading">
                <div>
                  <h2>Event Processing</h2>
                  <p>Events processed per investigation date</p>
                </div>
                <span className="live-label"><span /> Local data</span>
              </div>

              {chartData.length ? (
                <div className="chart-area">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData}>
                      <defs>
                        <linearGradient id="eventFill" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.28} />
                          <stop offset="95%" stopColor="#38bdf8" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid stroke="#202b3c" strokeDasharray="3 3" vertical={false} />
                      <XAxis dataKey="date" stroke="#64748b" tickLine={false} axisLine={false} />
                      <YAxis stroke="#64748b" tickLine={false} axisLine={false} />
                      <Tooltip contentStyle={{ background: '#111c2d', border: '1px solid #26364b', borderRadius: 8, color: '#e2e8f0' }} />
                      <Area type="monotone" dataKey="events" stroke="#38bdf8" strokeWidth={2} fill="url(#eventFill)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <EmptyState icon={BarChart3} title="No event history yet" text="Upload a security log to populate investigation analytics." />
              )}
            </section>

            <section className="panel severity-panel">
              <div className="panel-heading">
                <div><h2>Finding Severity</h2><p>Distribution across investigations</p></div>
              </div>
              <div className="severity-total">{totals.findings}<span>Total findings</span></div>
              <SeverityRow label="High / Critical" value={totals.high} total={totals.findings} color="#f87171" />
              <SeverityRow label="Medium" value={totals.medium} total={totals.findings} color="#fbbf24" />
              <SeverityRow label="Low" value={totals.low} total={totals.findings} color="#38bdf8" />
              <p className="muted small-note">Severity reflects rule output, not confirmed compromise.</p>
            </section>
          </div>

          <section className="panel table-panel">
            <div className="panel-heading">
              <div><h2>Recent Investigations</h2><p>Latest locally stored analysis runs</p></div>
              <button className="text-button" onClick={() => setPage('Investigations')}>
                View all <ChevronRight size={15} />
              </button>
            </div>
            <InvestigationTable items={investigations.slice(0, 5)} onSelect={setSelected} onDownload={downloadReport} />
          </section>
        </>
      )}

      {page === 'Investigations' && (
        <>
          <div className="page-heading">
            <div>
              <div className="eyebrow">SECURITY OPERATIONS / CASE MANAGEMENT</div>
              <h1>Investigations</h1>
              <p>Review saved analysis runs, findings and supporting evidence.</p>
            </div>
            <button className="button primary" onClick={() => setPage('Log Ingestion')}>
              <UploadCloud size={16} /> New investigation
            </button>
          </div>

          <section className="panel table-panel">
            <div className="toolbar">
              <div className="search-box">
                <Search size={16} />
                <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search file or investigation ID..." />
              </div>
              <button className="button secondary" onClick={() => void loadInvestigations()}>
                <RefreshCw size={15} /> Refresh
              </button>
            </div>
            <InvestigationTable items={filtered} onSelect={setSelected} onDownload={downloadReport} />
          </section>
        </>
      )}

      {page === 'Log Ingestion' && (
        <>
          <div className="page-heading">
            <div>
              <div className="eyebrow">SECURITY OPERATIONS / DATA INGESTION</div>
              <h1>Log Ingestion</h1>
              <p>Submit local Windows or normalized security event data for analysis.</p>
            </div>
          </div>

          <section className="panel upload-panel">
            <div className="upload-icon"><UploadCloud size={28} /></div>
            <h2>Upload security event logs</h2>
            <p>Choose a JSON or JSONL file. Files are processed locally by the SentinelTrace API.</p>
            <label className={`drop-zone ${uploading ? 'is-uploading' : ''}`}>
              {uploading ? <Loader2 className="spin" size={26} /> : <FolderOpen size={27} />}
              <strong>{uploading ? 'Analyzing security events...' : 'Select a log file'}</strong>
              <span>Supported formats: .json, .jsonl · Maximum size: 25 MB</span>
              <input
                type="file"
                accept=".json,.jsonl,application/json"
                disabled={uploading}
                onChange={(e) => {
                  void uploadFile(e.target.files?.[0])
                  e.currentTarget.value = ''
                }}
              />
            </label>
            <div className="upload-foot">
              <LockKeyhole size={15} />
              <span>Local processing · No cloud upload · No external AI service</span>
            </div>
          </section>

          <div className="info-grid">
            <InfoCard icon={FileText} title="Input validation" text="The parser accepts JSON arrays, JSON objects and JSONL records. Invalid records are counted and reported." />
            <InfoCard icon={Zap} title="Detection analysis" text="Enabled SentinelTrace rules correlate authentication, PowerShell and public-IP RDP indicators." />
            <InfoCard icon={Shield} title="Evidence-based output" text="Findings include rule metadata, evidence fingerprints and analyst recommendations." />
          </div>
        </>
      )}

      {page === 'Event Explorer' && (
        <>
          <div className="page-heading">
            <div>
              <div className="eyebrow">SECURITY OPERATIONS / EVENT ANALYSIS</div>
              <h1>Event Explorer</h1>
              <p>Search and inspect normalized security telemetry.</p>
            </div>
          </div>

          <section className="panel event-panel">
            <div className="event-toolbar">
              <label>
                Investigation
                <select
                  value={activeInvestigation}
                  onChange={(e) => {
                    setActiveInvestigation(e.target.value)
                    setEventPage(1)
                  }}
                >
                  {investigations.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.source_file} — {item.event_count} events
                    </option>
                  ))}
                </select>
              </label>

              <label>
                Search events
                <input value={eventSearch} onChange={(e) => {
                  setEventSearch(e.target.value)
                  setEventPage(1)
                }} placeholder="Search message, process, IP..." />
              </label>

              <label>
                Event ID
                <input value={eventIdFilter} onChange={(e) => {
                  setEventIdFilter(e.target.value)
                  setEventPage(1)
                }} placeholder="4624, 4625..." />
              </label>

              <label>
                Host
                <input value={hostFilter} onChange={(e) => {
                  setHostFilter(e.target.value)
                  setEventPage(1)
                }} placeholder="Hostname" />
              </label>

              <label>
                Severity
                <select value={severityFilter} onChange={(e) => {
                  setSeverityFilter(e.target.value)
                  setEventPage(1)
                }}>
                  <option value="">All severities</option>
                  {['critical', 'high', 'medium', 'low', 'informational', 'unknown'].map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </label>

              <label>
                Username
                <input value={usernameFilter} onChange={(e) => {
                  setUsernameFilter(e.target.value)
                  setEventPage(1)
                }} placeholder="Username" />
              </label>
            </div>

            <div className="panel-heading">
              <div>
                <h2>Normalized events</h2>
                <p>{eventTotal.toLocaleString()} matching records</p>
              </div>
              <button className="button secondary" onClick={() => void loadEvents()}>
                <RefreshCw size={15} /> Refresh
              </button>
            </div>

            {!activeInvestigation ? (
              <EmptyState icon={FolderOpen} title="No investigations available" text="Upload a log file to start exploring events." />
            ) : eventLoading ? (
              <EmptyState icon={Loader2} title="Loading events" text="Retrieving investigation telemetry..." />
            ) : events.length ? (
              <>
                <div className="table-scroll">
                  <table className="investigation-table">
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Event ID</th>
                        <th>Event type</th>
                        <th>Host</th>
                        <th>Username</th>
                        <th>Source IP</th>
                        <th>Severity</th>
                        <th>Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {events.map((event, index) => (
                        <tr key={`${event.fingerprint ?? event.timestamp}-${index}`}>
                          <td>{new Date(event.timestamp).toLocaleString()}</td>
                          <td>{event.event_id}</td>
                          <td>{event.event_type}</td>
                          <td>{event.host}</td>
                          <td>{event.username || '—'}</td>
                          <td>{event.source_ip || '—'}</td>
                          <td>{event.severity}</td>
                          <td>
                            <button className="text-button" onClick={() => setInspectedEvent(event)}>
                              Inspect <ChevronRight size={14} />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="event-pagination">
                  <span>Page {eventPage} of {eventPages} · {eventTotal.toLocaleString()} events</span>
                  <div>
                    <button
                      className="button secondary"
                      disabled={eventPage <= 1}
                      onClick={() => setEventPage((p) => p - 1)}
                    >
                      Previous
                    </button>
                    <button
                      className="button secondary"
                      disabled={eventPage >= eventPages}
                      onClick={() => setEventPage((p) => p + 1)}
                    >
                      Next
                    </button>
                  </div>
                </div>
              </>
            ) : (
              <EmptyState icon={Search} title="No events found" text="No records match these filters. Try changing or clearing your filters." />
            )}
          </section>
        </>
      )}

      {page === 'Evidence Timeline' && (
        <>
          <div className="page-heading">
            <div>
              <div className="eyebrow">SECURITY OPERATIONS / EVENT CORRELATION</div>
              <h1>Evidence Timeline</h1>
              <p>Chronological view of collected security events.</p>
            </div>
          </div>

          <section className="panel event-panel">
            <label className="timeline-selector">
              Investigation
              <select
                value={activeInvestigation}
                onChange={(e) => setActiveInvestigation(e.target.value)}
              >
                {investigations.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.source_file} — {item.event_count} events
                  </option>
                ))}
              </select>
            </label>

            <div className="panel-heading">
              <div>
                <h2>Event chronology</h2>
                <p>Showing up to 500 events in chronological order. Sequence alone does not establish causality.</p>
              </div>
              <button className="button secondary" onClick={() => void loadTimeline()}>
                <RefreshCw size={15} /> Refresh
              </button>
            </div>

            {!activeInvestigation ? (
              <EmptyState icon={FolderOpen} title="No investigations available" text="Upload a log file to create a timeline." />
            ) : eventLoading ? (
              <EmptyState icon={Loader2} title="Loading timeline" text="Retrieving chronological events..." />
            ) : timeline.length ? (
              <div className="timeline-list">
                {timeline.map((event, index) => (
                  <button
                    className="timeline-entry"
                    key={`${event.fingerprint ?? event.timestamp}-${index}`}
                    onClick={() => setInspectedEvent(event)}
                  >
                    <span className="timeline-marker" />
                    <span className="timeline-content">
                      <strong>{event.event_type || `Event ${event.event_id}`}</strong>
                      <span>{event.host} · {event.username || 'Unknown user'} · ID {event.event_id}</span>
                      <small>{new Date(event.timestamp).toLocaleString()}</small>
                      {event.message && <span>{event.message}</span>}
                    </span>
                    <ChevronRight size={16} />
                  </button>
                ))}
              </div>
            ) : (
              <EmptyState icon={Clock3} title="No timeline events" text="This investigation has no stored event records." />
            )}
          </section>
        </>
      )}

      {page === 'Reports' && (
        <>
          <div className="page-heading">
            <div>
              <div className="eyebrow">SECURITY OPERATIONS / REPORTING</div>
              <h1>Investigation Reports</h1>
              <p>Export structured investigation results for analyst review.</p>
            </div>
          </div>

          <section className="panel table-panel">
            <div className="panel-heading">
              <div><h2>Available reports</h2><p>JSON and Markdown exports from saved investigations</p></div>
            </div>
            {!investigations.length ? (
              <EmptyState icon={FileText} title="No reports available" text="Complete an investigation to generate reports." />
            ) : (
              <div className="table-scroll">
                <table className="investigation-table">
                  <thead>
                    <tr>
                      <th>Source file</th>
                      <th>Created</th>
                      <th>Events</th>
                      <th>Findings</th>
                      <th>Export</th>
                    </tr>
                  </thead>
                  <tbody>
                    {investigations.map((item) => (
                      <tr key={item.id}>
                        <td>{item.source_file}</td>
                        <td>{new Date(item.created_at).toLocaleString()}</td>
                        <td>{item.event_count.toLocaleString()}</td>
                        <td>{item.finding_count}</td>
                        <td>
                          <div className="action-group">
                            <button title="Download JSON report" onClick={() => void downloadReport(item)}>
                              <ArrowDownToLine size={16} /> JSON
                            </button>
                            <button title="Download Markdown report" onClick={() => void downloadMarkdown(item)}>
                              <FileText size={16} /> MD
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </>
  )

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileMenu ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <div className="brand-mark"><Shield size={22} /></div>
          <div><strong>SentinelTrace</strong><span>SOC INVESTIGATION</span></div>
          <button className="mobile-close" onClick={() => setMobileMenu(false)}>
            <X size={18} />
          </button>
        </div>

        <div className="nav-label">WORKSPACE</div>
        <nav>
          {navigation.map(({ name, icon: Icon }) => (
            <button
              key={name}
              className={`nav-item ${page === name ? 'active' : ''}`}
              onClick={() => {
                setPage(name)
                setMobileMenu(false)
              }}
            >
              <Icon size={18} />
              <span>{name}</span>
              {page === name && <span className="nav-indicator" />}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="engine-status">
            <span className="status-dot" />
            <div><strong>Local engine</strong><small>Offline-first analysis</small></div>
          </div>
          <div className="version">SENTINELTRACE · v0.2.0</div>
        </div>
      </aside>

      {mobileMenu && (
        <button className="mobile-overlay" onClick={() => setMobileMenu(false)} aria-label="Close menu" />
      )}

      <main className="main-area">
        <header className="topbar">
          <button className="mobile-menu-button" onClick={() => setMobileMenu(true)}>
            <Menu size={20} />
          </button>
          <div className="breadcrumb">Workspace <ChevronRight size={14} /> <strong>{page}</strong></div>
          <div className="topbar-right">
            <div className="api-indicator">
              <span className={error ? 'offline-dot' : 'status-dot'} />
              {error ? 'API unavailable / error' : 'Local API'}
            </div>
            <button className="icon-button" title="Refresh investigations" onClick={() => void loadInvestigations()}>
              <Bell size={17} />
            </button>
            <div className="avatar">ST</div>
          </div>
        </header>

        <div className="content">
          {loading && investigations.length === 0 ? (
            <div className="loading-state">
              <Loader2 className="spin" size={24} />
              <span>Loading investigation data...</span>
            </div>
          ) : content}

          <footer className="footer">
            <span>SentinelTrace · Evidence-based SOC investigation</span>
            <span>Local environment <ArrowUpRight size={13} /></span>
          </footer>
        </div>
      </main>

      {selected && (
        <InvestigationModal
          item={selected}
          onClose={() => setSelected(null)}
          onDownload={downloadReport}
        />
      )}

      {inspectedEvent && (
        <EventInspector
          event={inspectedEvent}
          onClose={() => setInspectedEvent(null)}
        />
      )}
    </div>
  )
}

function Metric({ icon: Icon, label, value, note }: {
  icon: typeof Activity
  label: string
  value: string
  note: string
}) {
  return (
    <div className="metric-card">
      <div className="metric-top">
        <span>{label}</span>
        <div className="metric-icon"><Icon size={18} /></div>
      </div>
      <strong className="metric-value">{value}</strong>
      <span className="metric-note">{note}</span>
    </div>
  )
}

function SeverityRow({ label, value, total, color }: {
  label: string
  value: number
  total: number
  color: string
}) {
  return (
    <div className="severity-row">
      <div><span>{label}</span><strong>{value}</strong></div>
      <div className="severity-track">
        <span style={{ width: `${total ? value / total * 100 : 0}%`, background: color }} />
      </div>
    </div>
  )
}

function InfoCard({ icon: Icon, title, text }: {
  icon: typeof FileText
  title: string
  text: string
}) {
  return (
    <div className="panel info-card">
      <Icon size={20} />
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  )
}

function EmptyState({ icon: Icon, title, text }: {
  icon: typeof BarChart3
  title: string
  text: string
}) {
  return (
    <div className="empty-state">
      <Icon size={26} />
      <strong>{title}</strong>
      <span>{text}</span>
    </div>
  )
}

function InvestigationTable({ items, onSelect, onDownload }: {
  items: Investigation[]
  onSelect: (item: Investigation) => void
  onDownload: (item: Investigation) => void
}) {
  if (!items.length) {
    return (
      <EmptyState
        icon={FolderOpen}
        title="No investigations found"
        text="Upload a JSON or JSONL log file to create your first investigation."
      />
    )
  }

  return (
    <div className="table-scroll">
      <table className="investigation-table">
        <thead>
          <tr>
            <th>Source file</th>
            <th>Created</th>
            <th>Events</th>
            <th>Findings</th>
            <th>Rejected</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <td>
                <button className="file-cell" onClick={() => onSelect(item)}>
                  <FileText size={16} />
                  <span>{item.source_file}</span>
                </button>
                <small className="table-id">{item.id.slice(0, 13)}...</small>
              </td>
              <td>{new Date(item.created_at).toLocaleString()}</td>
              <td>{item.event_count.toLocaleString()}</td>
              <td>
                <span className={`finding-count ${item.finding_count ? 'has-findings' : ''}`}>
                  {item.finding_count}
                </span>
              </td>
              <td>{item.rejected_count}</td>
              <td>
                <div className="action-group">
                  <button title="View investigation" onClick={() => onSelect(item)}>
                    <FileSearch size={16} />
                  </button>
                  <button title="Download JSON report" onClick={() => onDownload(item)}>
                    <ArrowDownToLine size={16} />
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function InvestigationModal({ item, onClose, onDownload }: {
  item: Investigation
  onClose: () => void
  onDownload: (item: Investigation) => void
}) {
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <section className="detail-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-heading">
          <div>
            <span className="eyebrow">INVESTIGATION DETAILS</span>
            <h2>{item.source_file}</h2>
          </div>
          <button className="icon-button" onClick={onClose}><X size={19} /></button>
        </div>

        <div className="detail-stats">
          <div><strong>{item.event_count.toLocaleString()}</strong><span>Events</span></div>
          <div><strong>{item.finding_count}</strong><span>Findings</span></div>
          <div><strong>{item.rejected_count}</strong><span>Rejected</span></div>
        </div>

        <p className="detail-id">Investigation ID: {item.id}</p>
        <p className="detail-date"><Clock3 size={14} /> {new Date(item.created_at).toLocaleString()}</p>
        <h3>Detection findings</h3>

        {(item.findings ?? []).length ? (
          (item.findings ?? []).map((finding, index) => (
            <div className="finding-card" key={`${finding.rule_id}-${index}`}>
              <div className="finding-heading">
                <strong>{finding.title}</strong>
                <span className={`severity-badge ${finding.severity.toLowerCase()}`}>
                  {finding.severity}
                </span>
              </div>
              <p>{finding.description}</p>
              <div className="finding-meta">
                {finding.rule_id} · Confidence: {finding.confidence} · Evidence items: {finding.evidence?.length ?? 0}
              </div>
              {finding.recommendations?.map((recommendation) => (
                <p className="recommendation" key={recommendation}>• {recommendation}</p>
              ))}
            </div>
          ))
        ) : (
          <EmptyState
            icon={CheckCircle2}
            title="No findings generated"
            text="No enabled detection rules matched this event set. This does not establish that the environment is safe."
          />
        )}

        <div className="modal-actions">
          <button className="button secondary" onClick={onClose}>Close</button>
          <button className="button primary" onClick={() => onDownload(item)}>
            <ArrowDownToLine size={15} /> Download JSON
          </button>
        </div>
      </section>
    </div>
  )
}

function EventInspector({ event, onClose }: {
  event: SecurityEvent
  onClose: () => void
}) {
  const fields: Array<[string, string | undefined]> = [
    ['Timestamp', event.timestamp],
    ['Event ID', event.event_id],
    ['Event type', event.event_type],
    ['Source', event.source],
    ['Host', event.host],
    ['Severity', event.severity],
    ['Username', event.username],
    ['Source IP', event.source_ip],
    ['Destination IP', event.destination_ip],
    ['Logon type', event.logon_type],
    ['Session ID', event.session_id],
    ['Session address', event.session_address],
    ['Process', event.process_name],
    ['Command line', event.command_line],
    ['Fingerprint', event.fingerprint],
    ['Message', event.message],
  ]

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <section className="detail-modal event-detail-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-heading">
          <div>
            <span className="eyebrow">EVENT INSPECTION</span>
            <h2>{event.event_type || `Event ${event.event_id}`}</h2>
          </div>
          <button className="icon-button" onClick={onClose}><X size={19} /></button>
        </div>

        <div className="event-detail-grid">
          {fields.map(([key, value]) => (
            <div key={key}>
              <span>{key}</span>
              <strong>{value || '—'}</strong>
            </div>
          ))}
        </div>

        <h3>Raw evidence</h3>
        <pre className="raw-evidence">
          {JSON.stringify(event.raw ?? {}, null, 2)}
        </pre>

        <div className="modal-actions">
          <button className="button secondary" onClick={onClose}>Close</button>
        </div>
      </section>
    </div>
  )
}

export default App

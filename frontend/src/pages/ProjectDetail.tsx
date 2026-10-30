import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api, getErrorMessage, authHeader } from '../api/client';
import type { Finding, Scan, Target } from '../types';

type Tab = 'targets' | 'scans' | 'findings' | 'assistant';

const sevClass = (s: string) => `sev sev-${s}`;
const confClass = (c: string) => (c === 'confirmed' ? 'tag tag-green' : 'tag tag-gray');

export default function ProjectDetail() {
  const { projectId = '' } = useParams();
  const [project, setProject] = useState<{ id: string; name: string; description?: string } | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [tab, setTab] = useState<Tab>('targets');
  const [error, setError] = useState('');
  const [aiOut, setAiOut] = useState('');
  const [aiQuestion, setAiQuestion] = useState('');

  // target form
  const [tName, setTName] = useState('');
  const [tKind, setTKind] = useState<'web' | 'infrastructure'>('web');
  const [tHost, setTHost] = useState('');
  const [tPort, setTPort] = useState('');
  const [tImportance, setTImportance] = useState(3);

  const load = useCallback(async () => {
    try {
      const [p, t, s, f] = await Promise.all([
        api.get(`/projects/${projectId}`),
        api.get(`/projects/${projectId}/targets`),
        api.get(`/projects/${projectId}/scans`),
        api.get(`/projects/${projectId}/findings`).catch(() => ({ data: { findings: [] } })),
      ]);
      setProject(p.data.project);
      setTargets(t.data.targets);
      setScans(s.data.scans);
      setFindings(f.data.findings ?? []);
    } catch (e) {
      setError(getErrorMessage(e));
    }
  }, [projectId]);

  useEffect(() => { load(); }, [load]);

  const addTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    try {
      await api.post('/targets', {
        projectId, name: tName, kind: tKind, host: tHost,
        port: tKind === 'infrastructure' && tPort ? Number(tPort) : null,
        importance: tImportance,
      });
      setTName(''); setTHost(''); setTPort('');
      load();
    } catch (err) { setError(getErrorMessage(err)); }
  };

  const generateToken = async (targetId: string) => {
    setError('');
    try {
      const res = await api.post<{ ownershipToken: string }>(`/targets/${targetId}/ownership-token`);
      alert(`Ownership token generated (deliver out-of-band to the target owner):\n\n${res.data.ownershipToken}`);
      load();
    } catch (err) { setError(getErrorMessage(err)); }
  };

  const verifyTarget = async (targetId: string) => {
    const ownershipToken = prompt('Enter the ownership token shown to you:');
    const ownershipOwner = prompt('Owner contact (email/phone):');
    if (!ownershipToken || !ownershipOwner) return;
    try {
      await api.post(`/targets/${targetId}/verify`, { ownershipToken, ownershipOwner });
      load();
    } catch (err) { setError(getErrorMessage(err)); }
  };

  const toggleAllowlist = async (targetId: string, allowlisted: boolean) => {
    try {
      await api.put(`/targets/${targetId}/allowlist`, { allowlisted: !allowlisted });
      load();
    } catch (err) { setError(getErrorMessage(err)); }
  };

  const runScan = async (targetId: string) => {
    const type = prompt('Scan type? (quick | full)', 'quick') ?? 'quick';
    const mode = prompt('Scan mode? (passive | active)', 'passive') ?? 'passive';
    setError('');
    try {
      await api.post('/scans', { targetId, type: type as 'quick' | 'full', mode: mode as 'passive' | 'active' });
      load();
      setTab('scans');
    } catch (err) { setError(getErrorMessage(err)); }
  };

  const updateFinding = async (findingId: string, status: Finding['status']) => {
    try {
      await api.patch(`/scans/findings/${findingId}/status`, { status });
      load();
    } catch (err) { setError(getErrorMessage(err)); }
  };

  const analyze = async () => {
    setAiOut('');
    try {
      const res = await api.post('/ai/analyze', { projectId, question: aiQuestion || undefined });
      const body = res.data;
      setAiOut(`${body.answer}`);
      setAiQuestion('');
    } catch (err) { setError(getErrorMessage(err)); }
  };

  const downloadReport = (scanId: string) => {
    const a = document.createElement('a');
    a.href = `/api/reports/scan/${scanId}`;
    a.setAttribute('download', `report-${scanId}.pdf`);
    const h = authHeader();
    if (h.Authorization) a.href += '';
    fetch(`/api/reports/scan/${scanId}`, { headers: h })
      .then((r) => r.blob())
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url; link.download = `report-${scanId}.pdf`;
        link.click();
        URL.revokeObjectURL(url);
      })
      .catch(() => setError('Report generation failed.'));
  };

  if (error) return <div className="alert alert-error">{error}</div>;
  if (!project) return <div className="muted">Loading project…</div>;

  const tabs: Array<{ key: Tab; label: string }> = [
    { key: 'targets', label: `Targets (${targets.length})` },
    { key: 'scans', label: `Scan history (${scans.length})` },
    { key: 'findings', label: `Findings (${findings.length})` },
    { key: 'assistant', label: 'AI Assistant' },
  ];

  return (
    <div>
      <header className="page-head">
        <div>
          <Link className="muted small" to="/projects">← Projects</Link>
          <h1>{project.name}</h1>
          {project.description && <p className="muted">{project.description}</p>}
        </div>
      </header>

      <nav className="tabs">
        {tabs.map((t) => (
          <button key={t.key} className={`tab${tab === t.key ? ' active' : ''}`} onClick={() => setTab(t.key)}>{t.label}</button>
        ))}
      </nav>

      {tab === 'targets' && (
        <div className="stack">
          <form className="panel inline-form" onSubmit={addTarget}>
            <input placeholder="Target name" value={tName} onChange={(e) => setTName(e.target.value)} required />
            <select value={tKind} onChange={(e) => setTKind(e.target.value as 'web' | 'infrastructure')}>
              <option value="web">Web / API</option>
              <option value="infrastructure">Infrastructure</option>
            </select>
            <input placeholder="Host / URL / IP" value={tHost} onChange={(e) => setTHost(e.target.value)} required />
            {tKind === 'infrastructure' && <input placeholder="Port (optional)" value={tPort} onChange={(e) => setTPort(e.target.value)} />}
            <input type="number" min={1} max={5} value={tImportance} onChange={(e) => setTImportance(Number(e.target.value))} title="Importance (1-5)" />
            <button className="btn btn-primary" type="submit">Add target</button>
          </form>

          {targets.map((t) => (
            <div className="panel target-row" key={t.id}>
              <div className="target-main">
                <div className="target-name">{t.name} <span className="tag">{t.kind}</span></div>
                <div className="muted small">{t.host}{t.port ? `:${t.port}` : ''} · importance {t.importance}</div>
              </div>
              <div className="target-badges">
                <span className={t.ownershipVerified ? 'tag tag-green' : 'tag tag-gray'}>
                  {t.ownershipVerified ? 'Ownership verified' : 'Not verified'}
                </span>
                <span className={t.allowlisted ? 'tag tag-blue' : 'tag tag-gray'}>
                  {t.allowlisted ? 'Allowlisted' : 'Not allowlisted'}
                </span>
              </div>
              <div className="target-actions">
                {!t.ownershipVerified && <button className="btn btn-sm" onClick={() => generateToken(t.id)}>Generate token</button>}
                {!t.ownershipVerified && <button className="btn btn-sm" onClick={() => verifyTarget(t.id)}>Verify ownership</button>}
                <button className="btn btn-sm" onClick={() => toggleAllowlist(t.id, t.allowlisted)}>
                  {t.allowlisted ? 'De-allowlist' : 'Allowlist'}
                </button>
                <button className="btn btn-sm btn-primary" disabled={!(t.ownershipVerified && t.allowlisted)} onClick={() => runScan(t.id)}>
                  Run scan
                </button>
              </div>
            </div>
          ))}
          {targets.length === 0 && <p className="muted">No targets yet. Add your first authorized target above (it must be ownership-verified and allowlisted before it can be scanned).</p>}
        </div>
      )}

      {tab === 'scans' && (
        <div className="panel">
          <table>
            <thead><tr><th>Target</th><th>Type/Mode</th><th>Status</th><th>Started</th><th>Finished</th><th>Report</th></tr></thead>
            <tbody>
              {scans.map((s) => {
                const trg = targets.find((t) => t.id === s.targetId);
                return (
                  <tr key={s.id}>
                    <td>{trg?.name ?? s.targetId}</td>
                    <td>{s.type}/{s.mode}</td>
                    <td><span className={`tag tag-${s.status === 'completed' ? 'green' : s.status === 'failed' ? 'red' : 'gray'}`}>{s.status}</span></td>
                    <td>{s.startedAt ? new Date(s.startedAt).toLocaleString() : '-'}</td>
                    <td>{s.finishedAt ? new Date(s.finishedAt).toLocaleString() : '-'}</td>
                    <td>{s.status === 'completed' && <button className="btn btn-sm" onClick={() => downloadReport(s.id)}>PDF</button>}</td>
                  </tr>
                );
              })}
              {scans.length === 0 && <tr><td colSpan={6}>No scans recorded yet.</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'findings' && (
        <div className="stack">
          {[...findings].sort((a, b) => sevRank(b.severity) - sevRank(a.severity)).map((f) => (
            <div className="panel finding" key={f.id}>
              <div className="finding-head">
                <span className={sevClass(f.severity)}>{f.severity.toUpperCase()}</span>
                <strong>{f.title}</strong>
                <span className={confClass(f.confidence)}>{f.confidence}</span>
              </div>
              <p className="small">{f.description}</p>
              <div className="finding-meta small muted">
                {f.cvssScore != null && <span>CVSS {f.cvssScore}</span>}
                {f.cweId && <span>{f.cweId}</span>}
                {f.cveId && <span>{f.cveId}</span>}
                <span>detector: {f.detector}</span>
              </div>
              {f.evidence && <pre className="evidence">{f.evidence}</pre>}
              {f.remediation && <p className="small"><strong>Remediation:</strong> {f.remediation}</p>}
              <div className="finding-actions">
                <select value={f.status} onChange={(e) => updateFinding(f.id, e.target.value as Finding['status'])}>
                  <option value="open">Open</option>
                  <option value="in_progress">In progress</option>
                  <option value="remediated">Remediated</option>
                  <option value="false_positive">False positive</option>
                </select>
              </div>
            </div>
          ))}
          {findings.length === 0 && <p className="muted">No findings yet — run a scan to populate findings.</p>}
        </div>
      )}

      {tab === 'assistant' && (
        <div className="panel stack">
          <p className="muted">Generate an executive summary or ask a question grounded in this project's scan evidence.</p>
          <form className="inline-form" onSubmit={(e) => { e.preventDefault(); analyze(); }}>
            <input placeholder="e.g. Summarize findings, or: how do I remediate the critical issue?" value={aiQuestion} onChange={(e) => setAiQuestion(e.target.value)} />
            <button className="btn btn-primary" type="submit">Ask / Summarize</button>
          </form>
          {aiOut && <pre className="evidence">{aiOut}</pre>}
        </div>
      )}
    </div>
  );
}

function sevRank(s: string): number {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] ?? 0;
}


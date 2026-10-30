import { useState } from 'react';
import { api, getErrorMessage } from '../api/client';

interface Cve {
  id: string;
  published: string | null;
  description: string;
  cvssV3: number | null;
  cvssV2: number | null;
  severity: string | null;
  cwes: string[];
  references: string[];
  affectedProducts: string[];
}

export default function CveLookup() {
  const [keyword, setKeyword] = useState('');
  const [cveId, setCveId] = useState('');
  const [records, setRecords] = useState<Cve[]>([]);
  const [detail, setDetail] = useState<Cve | null>(null);
  const [error, setError] = useState('');
  const [note, setNote] = useState('');

  const search = async () => {
    setError(''); setDetail(null); setNote('');
    if (!keyword.trim()) return;
    try {
      const res = await api.post<{ records: Cve[] }>('/cve/search', { keyword });
      setRecords(res.data.records);
      setNote('NVD version matches are advisory and do not prove exploitability.');
    } catch (e) { setError(getErrorMessage(e)); }
  };

  const lookup = async () => {
    setError(''); setRecords([]); setNote('');
    const id = cveId.trim().toUpperCase();
    if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return setError('Enter a valid CVE id, e.g. CVE-2024-1234');
    try {
      const res = await api.get<{ record: Cve }>(`/cve/${id}`);
      setDetail(res.data.record);
    } catch (e) { setError(getErrorMessage(e)); }
  };

  const cveCard = (c: Cve) => (
    <div className="panel cve-card" key={c.id}>
      <div className="cve-head">
        <strong>{c.id}</strong>
        <span className="tag tag-blue">CVSS: {c.cvssV3 ?? c.cvssV2 ?? 'n/a'} {c.severity ? `(${c.severity})` : ''}</span>
      </div>
      <p className="small">{c.description}</p>
      {c.cwes.length > 0 && <div className="muted small">CWE: {c.cwes.join(', ')}</div>}
      {c.references.slice(0, 4).map((r) => <div key={r} className="small">• <a href={r} target="_blank" rel="noreferrer">{r}</a></div>)}
      <button className="btn btn-sm" onClick={() => setDetail(c)}>Details</button>
    </div>
  );

  return (
    <div>
      <header className="page-head">
        <div><h1>CVE Lookup</h1><p className="muted">National Vulnerability Database intelligence: CVEs, CWEs, CVSS, affected versions and references.</p></div>
      </header>
      <div className="panel stack">
        <label>Search by keyword / technology
          <div className="inline-form">
            <input value={keyword} onChange={(e) => setKeyword(e.target.value)} placeholder="e.g. nginx 1.18" onKeyDown={(e) => e.key === 'Enter' && search()} />
            <button className="btn btn-primary" onClick={search}>Search NVD</button>
          </div>
        </label>
        <label>Lookup by CVE ID
          <div className="inline-form">
            <input value={cveId} onChange={(e) => setCveId(e.target.value)} placeholder="CVE-2024-1234" />
            <button className="btn" onClick={lookup}>Lookup</button>
          </div>
        </label>
        {note && <div className="alert">{note}</div>}
        {error && <div className="alert alert-error">{error}</div>}
      </div>

      {detail && (
        <div className="panel stack">
          <div className="cve-head"><h2>{detail.id}</h2><button className="btn btn-sm" onClick={() => setDetail(null)}>Close</button></div>
          <p>{detail.description}</p>
          <div className="muted small">Published: {detail.published ?? 'n/a'}</div>
          <div className="muted small">CVSS v3: {detail.cvssV3 ?? 'n/a'} · CVSS v2: {detail.cvssV2 ?? 'n/a'}</div>
          <div className="muted small">CWEs: {detail.cwes.join(', ') || 'none'}</div>
          {detail.affectedProducts.length > 0 && (
            <div><strong className="small">Affected (CPE):</strong>
              <pre className="evidence">{detail.affectedProducts.slice(0, 10).join('\n')}</pre>
            </div>
          )}
          <div><strong className="small">References:</strong>
            {detail.references.map((r) => <div key={r} className="small">• <a href={r} target="_blank" rel="noreferrer">{r}</a></div>)}
          </div>
        </div>
      )}

      <div className="stack cve-list">{records.map(cveCard)}</div>
    </div>
  );
}

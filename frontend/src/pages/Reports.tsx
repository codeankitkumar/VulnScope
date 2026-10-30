import { useEffect, useState } from 'react';
import { api, getErrorMessage, authHeader } from '../api/client';
import type { Project, Scan } from '../types';

export default function Reports() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [scansByProject, setScansByProject] = useState<Record<string, Scan[]>>({});
  const [error, setError] = useState('');

  useEffect(() => {
    api.get<{ projects: Project[] }>('/projects')
      .then(async (r) => {
        const projects = r.data.projects;
        setProjects(projects);
        const map: Record<string, Scan[]> = {};
        await Promise.all(projects.map(async (p) => {
          try {
            const s = await api.get<{ scans: Scan[] }>(`/projects/${p.id}/scans`);
            map[p.id] = s.data.scans;
          } catch { map[p.id] = []; }
        }));
        setScansByProject(map);
      })
      .catch((e) => setError(getErrorMessage(e)));
  }, []);

  const download = async (scanId: string) => {
    try {
      const res = await fetch(`/api/reports/scan/${scanId}`, { headers: authHeader() });
      if (!res.ok) throw new Error(getErrorMessage({ response: { data: { error: `HTTP ${res.status}` } } }));
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `vulnscope-report-${scanId}.pdf`; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { setError(getErrorMessage(e)); }
  };

  if (error) return <div className="alert alert-error">{error}</div>;

  return (
    <div>
      <header className="page-head">
        <div><h1>Reports</h1><p className="muted">Generate PDF reports per completed scan — scope, methodology, findings, evidence, risk, and remediation.</p></div>
      </header>
      <div className="stack">
        {projects.map((p) => {
          const scans = scansByProject[p.id] ?? [];
          return (
            <section className="panel" key={p.id}>
              <h2 className="panel-title">{p.name}</h2>
              {scans.filter((s) => s.status === 'completed').length === 0 && <p className="muted">No completed scans to report.</p>}
              <table>
                <thead><tr><th>Scan</th><th>Type/Mode</th><th>Completed</th><th></th></tr></thead>
                <tbody>
                  {scans.filter((s) => s.status === 'completed').map((s) => (
                    <tr key={s.id}>
                      <td className="small">{s.id}</td>
                      <td>{s.type}/{s.mode}</td>
                      <td>{s.finishedAt ? new Date(s.finishedAt).toLocaleString() : '-'}</td>
                      <td><button className="btn btn-sm btn-primary" onClick={() => download(s.id)}>Download PDF</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          );
        })}
        {projects.length === 0 && <p className="muted">Create a project and run a scan to generate reports.</p>}
      </div>
    </div>
  );
}

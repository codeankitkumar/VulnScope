import { useEffect, useState } from 'react';
import { api, getErrorMessage } from '../api/client';
import type { Project } from '../types';

export default function Assistant() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState('');
  const [question, setQuestion] = useState('');
  const [output, setOutput] = useState('');

  useEffect(() => {
    api.get<{ projects: Project[] }>('/projects').then((r) => {
      setProjects(r.data.projects);
      if (r.data.projects[0] && !projectId) setProjectId(r.data.projects[0].id);
    }).catch((e) => setError(e));
  }, []);

  const setError = (e: unknown) => setOutput(getErrorMessage(e));

  const analyze = async () => {
    setOutput('Thinking…');
    try {
      const res = await api.post('/ai/analyze', { projectId, question: question || undefined });
      setOutput(format(res.data));
    } catch (e) { setError(e); }
  };

  const group = async () => {
    setOutput('Grouping…');
    try {
      const res = await api.post('/ai/group', { projectId });
      setOutput(res.data.groups
        .map((g: { group: string; rationale: string; findings: string[] }) => `## ${g.group}\n${g.rationale}\nCount: ${g.findings.length}`)
        .join('\n\n'));
    } catch (e) { setError(e); }
  };

  const enrich = async () => {
    setOutput('Enriching with NVD data…');
    try {
      const res = await api.post('/ai/cve-enrich', { projectId });
      const fs = res.data.findings as Array<{ title: string; cveId?: string | null; cvssScore?: number | null }>;
      setOutput(fs.map((f) => `- ${f.title}${f.cveId ? ` [${f.cveId}]` : ''}${f.cvssScore != null ? ` CVSS ${f.cvssScore}` : ''}`).join('\n'));
    } catch (e) { setError(e); }
  };

  return (
    <div>
      <header className="page-head">
        <div><h1>AI Security Assistant</h1><p className="muted">Every answer references actual scan evidence and distinguishes confirmed vs. possible findings.</p></div>
      </header>
      <div className="panel stack">
        <label>Project
          <select value={projectId} onChange={(e) => setProjectId(e.target.value)}>
            {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </label>
        <div className="inline-form">
          <input value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="Ask about this project's findings, e.g. 'Which issues are critical and how do I remediate them?'" />
          <button className="btn btn-primary" onClick={analyze}>Ask</button>
        </div>
        <div className="inline-form">
          <button className="btn" onClick={() => { setQuestion(''); analyze(); }}>Executive summary</button>
          <button className="btn" onClick={group}>Group related findings</button>
          <button className="btn" onClick={enrich}>Enrich with CVEs</button>
        </div>
        {output && <pre className="evidence">{output}</pre>}
      </div>
    </div>
  );

  function format(d: { answer: string; sections?: Array<{ heading: string; body: string }> }) {
    if (d.sections?.length) {
      return d.sections.map((s) => `## ${s.heading}\n${s.body}`).join('\n\n');
    }
    return d.answer;
  }
}

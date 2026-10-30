import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, getErrorMessage } from '../api/client';
import type { Project } from '../types';

export default function Projects() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const load = () => {
    api.get<{ projects: Project[] }>('/projects')
      .then((res) => setProjects(res.data.projects))
      .catch((e) => setError(getErrorMessage(e)));
  };
  useEffect(load, []);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError('');
    try {
      await api.post('/projects', { name, description });
      setName('');
      setDescription('');
      load();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const removeProject = async (id: string) => {
    if (!confirm('Delete this project and all its data?')) return;
    try {
      await api.delete(`/projects/${id}`);
      load();
    } catch (e) {
      setError(getErrorMessage(e));
    }
  };

  return (
    <div>
      <header className="page-head">
        <div>
          <h1>Projects</h1>
          <p className="muted">Group authorized targets into assessment scopes.</p>
        </div>
      </header>

      <form className="inline-form panel" onSubmit={create}>
        <input placeholder="Project name" value={name} onChange={(e) => setName(e.target.value)} required />
        <input placeholder="Description (optional)" value={description} onChange={(e) => setDescription(e.target.value)} />
        <button className="btn btn-primary" type="submit" disabled={busy}>Create project</button>
      </form>
      {error && <div className="alert alert-error">{error}</div>}

      <div className="project-grid">
        {projects.map((p) => (
          <div className="panel project-card" key={p.id}>
            <div className="project-name">{p.name}</div>
            {p.description && <p className="muted small">{p.description}</p>}
            <div className="project-actions">
              <Link className="btn btn-sm" to={`/projects/${p.id}`}>Open</Link>
              <button className="btn btn-sm btn-danger-ghost" onClick={() => removeProject(p.id)}>Delete</button>
            </div>
          </div>
        ))}
        {projects.length === 0 && <p className="muted">No projects yet. Create your first assessment scope above.</p>}
      </div>
    </div>
  );
}

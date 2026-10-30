import { useEffect, useState } from 'react';
import { api, getErrorMessage } from '../api/client';

interface Log {
  id: string;
  actorId: string | null;
  action: string;
  entity: string;
  entityId: string | null;
  metadata: string | null;
  ip: string | null;
  createdAt: string;
}

export default function Audit() {
  const [logs, setLogs] = useState<Log[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    api.get<{ logs: Log[] }>('/audit')
      .then((r) => setLogs(r.data.logs))
      .catch((e) => setError(getErrorMessage(e)));
  }, []);

  if (error) return <div className="alert alert-error">Admin access required: {error}</div>;

  return (
    <div>
      <header className="page-head">
        <div><h1>Audit Log</h1><p className="muted">Administrative record of every meaningful action (admin only).</p></div>
      </header>
      <div className="panel">
        <table>
          <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Entity</th><th>Entity ID</th><th>IP</th></tr></thead>
          <tbody>
            {logs.map((l) => (
              <tr key={l.id}>
                <td className="small">{new Date(l.createdAt).toLocaleString()}</td>
                <td className="small">{l.actorId?.slice(0, 8) ?? 'system'}</td>
                <td><span className="tag">{l.action}</span></td>
                <td>{l.entity}</td>
                <td className="small">{l.entityId ?? '-'}</td>
                <td className="small">{l.ip ?? '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

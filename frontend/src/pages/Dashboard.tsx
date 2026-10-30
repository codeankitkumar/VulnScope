import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import type { DashboardStats } from '../types';

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    api.get<{ stats: DashboardStats }>('/dashboard')
      .then((res) => setStats(res.data.stats))
      .catch(() => setError('Failed to load dashboard metrics.'));
  }, []);

  if (error) return <div className="alert alert-error">{error}</div>;
  if (!stats) return <div className="muted">Loading dashboard…</div>;

  const cards = [
    { label: 'Assets', value: stats.assets, tone: 'blue' },
    { label: 'Completed scans', value: stats.completedScans, tone: 'green' },
    { label: 'Open vulnerabilities', value: stats.openVulnerabilities, tone: 'orange' },
    { label: 'Critical findings', value: stats.critical, tone: 'red' },
  ];

  const maxTrend = Math.max(1, ...stats.riskTrend.map((t) => t.count));
  const maxDist = Math.max(1, ...stats.severityDistribution.map((d) => d.count));

  return (
    <div>
      <header className="page-head">
        <div>
          <h1>Dashboard</h1>
          <p className="muted">Overview of your authorized assessment program.</p>
        </div>
        <Link className="btn btn-primary" to="/projects">Manage projects</Link>
      </header>

      <div className="stat-grid">
        {cards.map((c) => (
          <div key={c.label} className={`stat-card stat-${c.tone}`}>
            <div className="stat-value">{c.value}</div>
            <div className="stat-label">{c.label}</div>
          </div>
        ))}
      </div>

      <div className="grid-2">
        <section className="panel">
          <h2 className="panel-title">Vulnerability distribution</h2>
          {stats.severityDistribution.map((d) => (
            <div className="bar-row" key={d.severity}>
              <span className="bar-label">{d.severity}</span>
              <div className="bar-track">
                <div className={`bar bar-${d.severity}`} style={{ width: `${(d.count / maxDist) * 100}%` }} />
              </div>
              <span className="bar-value">{d.count}</span>
            </div>
          ))}
        </section>

        <section className="panel">
          <h2 className="panel-title">Risk trend (high + critical, 14 days)</h2>
          <div className="trend-bars">
            {stats.riskTrend.map((t) => (
              <div className="trend-col" key={t.date} title={`${t.date}: ${t.count}`}>
                <div className="trend-val">{t.count > 0 ? t.count : ''}</div>
                <div className="trend-bar" style={{ height: `${(t.count / maxTrend) * 100}%` }} />
                <div className="trend-label">{t.date.slice(5)}</div>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="panel">
        <h2 className="panel-title">Remediation progress</h2>
        <div className="stat-chip-row">
          <span className="chip">Open: {stats.remediationProgress.open}</span>
          <span className="chip">In progress: {stats.remediationProgress.inProgress}</span>
          <span className="chip chip-green">Remediated: {stats.remediationProgress.remediated}</span>
          <span className="chip chip-gray">False positive: {stats.remediationProgress.falsePositive}</span>
        </div>
      </section>
    </div>
  );
}

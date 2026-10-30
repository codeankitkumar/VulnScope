import type { ReactNode } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Layout({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => { logout(); navigate('/login'); };

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">VS</span><span className="brand-name">VulnScope</span></div>
        <div className="sidebar-section">
          <div className="sidebar-label">Workspace</div>
          <NavLink to="/" end className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>Dashboard</NavLink>
          <NavLink to="/projects" className={() => `nav-link${['/projects'].includes(location.pathname) && !/\/projects\/.+/.test(location.pathname) ? ' active' : ''}`}>Projects</NavLink>
          <NavLink to="/reports" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>Reports</NavLink>
        </div>
        <div className="sidebar-section">
          <div className="sidebar-label">Intelligence</div>
          <NavLink to="/assistant" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>AI Assistant</NavLink>
          <NavLink to="/cve" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>CVE Lookup</NavLink>
        </div>
        {user?.role === 'admin' && (
          <div className="sidebar-section">
            <div className="sidebar-label">Administration</div>
            <NavLink to="/audit" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>Audit log</NavLink>
          </div>
        )}
        <div className="sidebar-footer">
          <div className="user-chip">
            <div className="user-name">{user?.name ?? 'User'}</div>
            <div className="user-role">{user?.role}</div>
          </div>
          <button className="btn btn-ghost" onClick={handleLogout}>Sign out</button>
        </div>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}

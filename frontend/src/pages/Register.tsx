import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Register() {
  const { register, loading, error } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [localError, setLocalError] = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError('');
    if (password.length < 8) return setLocalError('Password must be at least 8 characters.');
    if (password !== confirm) return setLocalError('Passwords do not match.');
    try {
      await register(email, name, password);
      navigate('/');
    } catch {
      /* context error */
    }
  };

  return (
    <div className="auth-card">
      <div className="auth-brand">
        <span className="brand-mark large">VS</span>
        <h1>Create account</h1>
        <p>Join VulnScope to start assessing authorized targets</p>
      </div>
      <form onSubmit={submit} className="auth-form">
        <label>Full name
          <input value={name} onChange={(e) => setName(e.target.value)} required />
        </label>
        <label>Email
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
        </label>
        <label>Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="new-password" />
        </label>
        <label>Confirm password
          <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required autoComplete="new-password" />
        </label>
        {(error || localError) && <div className="alert alert-error">{error || localError}</div>}
        <button className="btn btn-primary btn-block" type="submit" disabled={loading}>
          {loading ? 'Creating account…' : 'Create account'}
        </button>
      </form>
      <p className="muted">
        Already have an account? <Link to="/login">Sign in</Link>
      </p>
    </div>
  );
}

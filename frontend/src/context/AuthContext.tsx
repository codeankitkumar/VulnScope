import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { api, getErrorMessage } from '../api/client';
import type { PublicUser } from '../types';

interface AuthState {
  user: PublicUser | null;
  token: string | null;
  loading: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, name: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<PublicUser | null>(() => {
    try {
      const raw = localStorage.getItem('vulnscope_user');
      return raw ? (JSON.parse(raw) as PublicUser) : null;
    } catch {
      return null;
    }
  });
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('vulnscope_token'));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const persist = (t: string, u: PublicUser) => {
    localStorage.setItem('vulnscope_token', t);
    localStorage.setItem('vulnscope_user', JSON.stringify(u));
    setToken(t);
    setUser(u);
  };

  const login = async (email: string, password: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.post('/auth/login', { email, password });
      persist(res.data.token, res.data.user);
    } catch (e) {
      setError(getErrorMessage(e, 'Login failed.'));
      throw e;
    } finally {
      setLoading(false);
    }
  };

  const register = async (email: string, name: string, password: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.post('/auth/register', { email, name, password });
      persist(res.data.token, res.data.user);
    } catch (e) {
      setError(getErrorMessage(e, 'Registration failed.'));
      throw e;
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem('vulnscope_token');
    localStorage.removeItem('vulnscope_user');
    setToken(null);
    setUser(null);
  };

  useEffect(() => {
    if (!token || user) return;
  }, [token, user]);

  return (
    <AuthContext.Provider value={{ user, token, loading, error, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

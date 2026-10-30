import axios from 'axios';

export const api = axios.create({ baseURL: '/api' });

api.interceptors.request.use((cfg) => {
  const token = localStorage.getItem('vulnscope_token');
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  return cfg;
});

api.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error?.response?.status === 401) {
      localStorage.removeItem('vulnscope_token');
      localStorage.removeItem('vulnscope_user');
      if (window.location.pathname !== '/login') window.location.assign('/login');
    }
    return Promise.reject(error);
  },
);

export function getErrorMessage(error: unknown, fallback = 'An unexpected error occurred.'): string {
  const anyErr = error as { response?: { data?: { error?: string; details?: Array<{ message?: string }> } } };
  if (anyErr?.response?.data?.error) return anyErr.response.data.error;
  return fallback;
}

export function authHeader(): Record<string, string> {
  const token = localStorage.getItem('vulnscope_token');
  return token ? { Authorization: 'Bearer ' + token } : {};
}

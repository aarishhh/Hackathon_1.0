import React, { useState, useEffect } from 'react';
import LoginForm from './components/LoginForm';
import Dashboard from './components/Dashboard';
import Hero from './components/Hero';

export default function App() {
  // mode: 'insecure' | 'secure'
  const [mode, setMode] = useState('insecure');
  const [token, setToken] = useState(null);
  const [profile, setProfile] = useState(null);

  // backend base URLs (toggle to demo insecure vs secure)
  const backends = {
    insecure: 'http://localhost:3001/api',
    secure: 'http://localhost:3001/api' // for demo; in real secure mode use https or another port
  };

  const apiBase = backends[mode];

  // try to keep token only in memory for the demo
  useEffect(() => {
    // simple profile fetch when token changes
    async function fetchProfile() {
      if (!token) {
        setProfile(null);
        return;
      }
      try {
        const res = await fetch(`${apiBase}/profile`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) throw new Error('Failed to fetch profile');
        const data = await res.json();
        setProfile(data);
      } catch (err) {
        console.error(err);
        setProfile(null);
      }
    }
    fetchProfile();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, apiBase]);

  const handleLogout = () => {
    setToken(null);
    setProfile(null);
  };

  return (
    <div className="app-root">
      <header className="topbar">
        <div className="brand">
          <div className="logo">🛡️</div>
          <div>
            <div className="title">Project Aegis</div>
            <div className="subtitle">Digi-Swasthya — Security-first demo</div>
          </div>
        </div>

        <div className="controls">
          <div className="mode-toggle">
            <label className={`pill ${mode === 'insecure' ? 'active' : ''}`}>
              <input
                type="radio"
                name="mode"
                checked={mode === 'insecure'}
                onChange={() => setMode('insecure')}
              />
              Insecure
            </label>
            <label className={`pill ${mode === 'secure' ? 'active' : ''}`}>
              <input
                type="radio"
                name="mode"
                checked={mode === 'secure'}
                onChange={() => setMode('secure')}
              />
              Secure
            </label>
          </div>
          <div className="env-note">API: <code>{apiBase}</code></div>
        </div>
      </header>

      <main className="main">
        <Hero />

        {!token ? (
          <div className="panel">
            <h3 className="panel-title">Sign in to demo</h3>
            <LoginForm
              apiBase={apiBase}
              onSuccess={(jwt) => setToken(jwt)}
              demoMode={mode}
            />
            <div className="help">
              Tip: Use <code>alice / securePa$$word123</code> after you register on the backend.
            </div>
          </div>
        ) : (
          <Dashboard profile={profile} token={token} onLogout={handleLogout} />
        )}
      </main>

      <footer className="footer">
        <div>Team Axiom — Project Aegis · Hackathon Demo</div>
        <div className="small">Built for education — do not use insecure mode on production data.</div>
      </footer>
    </div>
  );
}

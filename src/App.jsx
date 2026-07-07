import { useEffect, useState } from 'react';

const API_BASE = '/api';

function formatDuration(milliseconds) {
  const safeMilliseconds = Math.max(0, milliseconds);
  const totalSeconds = Math.ceil(safeMilliseconds / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;

  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

function App() {
  const [rc, setRc] = useState('');
  const [status, setStatus] = useState('');
  const [result, setResult] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showScrollTop, setShowScrollTop] = useState(false);
  const [verified, setVerified] = useState(false);
  const [accessCode, setAccessCode] = useState('');
  const [accessError, setAccessError] = useState('');
  const [sessionExpiresAt, setSessionExpiresAt] = useState(null);
  const [sessionNow, setSessionNow] = useState(Date.now());
  const [isSessionChecking, setIsSessionChecking] = useState(true);
  const [sessionMessage, setSessionMessage] = useState('');

  function resetState() {
    setRc('');
    setStatus('');
    setResult('');
    setIsLoading(false);
  }

  function clearSessionState({ showMessage = false, message = '' } = {}) {
    setVerified(false);
    setSessionExpiresAt(null);
    setRc('');
    setStatus('');
    setResult('');
    setIsLoading(false);
    setAccessCode('');
    setAccessError(showMessage ? message : '');
    setSessionMessage(showMessage ? message : '');
  }

  useEffect(() => {
    const handleScroll = () => {
      setShowScrollTop(window.scrollY > 240);
    };

    let cancelled = false;

    async function loadSession() {
      try {
        const response = await fetch(`${API_BASE}/session`, {
          credentials: 'include',
        });

        const data = await response.json();

        if (cancelled) {
          return;
        }

        if (response.ok && data.authenticated) {
          setVerified(true);
          setSessionExpiresAt(data.expiresAt);
          setAccessError('');
          setSessionMessage('');
        } else {
          setVerified(false);
          setSessionExpiresAt(null);
        }
      } catch (error) {
        if (!cancelled) {
          setSessionMessage('Unable to verify the current session.');
        }
      } finally {
        if (!cancelled) {
          setIsSessionChecking(false);
        }
      }
    }

    window.addEventListener('scroll', handleScroll);
    loadSession();
    handleScroll();

    const sessionPoll = window.setInterval(loadSession, 30000);
    const clockTick = window.setInterval(() => setSessionNow(Date.now()), 1000);

    return () => {
      cancelled = true;
      window.removeEventListener('scroll', handleScroll);
      window.clearInterval(sessionPoll);
      window.clearInterval(clockTick);
    };
  }, []);

  useEffect(() => {
    if (!verified || !sessionExpiresAt) {
      return undefined;
    }

    const remaining = sessionExpiresAt - Date.now();

    if (remaining <= 0) {
      clearSessionState({
        showMessage: true,
        message: 'Session timed out. Please sign in again.',
      });
      return undefined;
    }

    const timeoutId = window.setTimeout(() => {
      clearSessionState({
        showMessage: true,
        message: 'Session timed out. Please sign in again.',
      });
    }, remaining);

    return () => window.clearTimeout(timeoutId);
  }, [verified, sessionExpiresAt]);

  async function verifyAccess(event) {
    event.preventDefault();

    try {
      const response = await fetch(`${API_BASE}/verify`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: accessCode.trim() }),
      });

      const data = await response.json();

      if (response.ok && data.ok) {
        setVerified(true);
        setSessionExpiresAt(data.expiresAt || null);
        setAccessError('');
        setSessionMessage('');
      } else {
        setAccessError(data.error || 'Incorrect access code. Please try again.');
        setAccessCode('');
      }
    } catch (error) {
      setAccessError('Verification service is unavailable.');
      setAccessCode('');
    }
  }

  async function endSession() {
    try {
      await fetch(`${API_BASE}/logout`, {
        method: 'POST',
        credentials: 'include',
      });
    } catch (error) {
      // Continue clearing the client session even if the network request fails.
    } finally {
      clearSessionState();
    }
  }

  function scrollToTop() {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  async function lookup() {
    const queryText = rc.trim();

    if (!queryText) {
      setStatus('Please enter an identifier, plate, or subject.');
      setResult('');
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    setStatus('Analyzing…');
    setResult('');

    try {
      const response = await fetch(`${API_BASE}/lookup?rc=${encodeURIComponent(queryText)}`, {
        credentials: 'include',
      });
      const data = await response.json();
      setStatus(response.ok ? 'Analysis complete.' : 'Request issue.');
      setResult(JSON.stringify(data, null, 2));
    } catch (error) {
      setStatus('Analysis failed.');
      setResult(error.message);
    } finally {
      setIsLoading(false);
    }
  }

  if (!verified) {
    return (
      <div className="page-shell">
        <div className="gate-card">
          <p className="eyebrow">Restricted access</p>
          <h1>Verification required</h1>
          <p className="gate-text">
            Enter the access code to continue into the OSINT workspace.
          </p>

          {isSessionChecking ? <div className="gate-error">Checking session status…</div> : null}
          {sessionMessage ? <div className="gate-error">{sessionMessage}</div> : null}

          <form className="gate-form" onSubmit={verifyAccess}>
            <input
              value={accessCode}
              onChange={(event) => setAccessCode(event.target.value)}
              placeholder="Enter access code"
              type="password"
            />
            <button type="submit">Continue</button>
          </form>

          {accessError ? <div className="gate-error">{accessError}</div> : null}
        </div>
      </div>
    );
  }

  return (
    <div className="page-shell">
      <div className="card">
        <div className="card-header">
          <div>
            <p className="eyebrow">Vehicle Details</p>
            <h1>Find vehicle records</h1>
            {sessionExpiresAt ? (
              <p className="gate-text" style={{ marginTop: '0.75rem' }}>
                Session active for {formatDuration(sessionExpiresAt - sessionNow)} more.
              </p>
            ) : null}
          </div>
          <button type="button" className="refresh-btn" onClick={endSession} aria-label="End session" title="End session">
            <span className="refresh-icon" aria-hidden="true">Exit</span>
          </button>
        </div>

        <div className="search-panel">
          <div className="search-row">
            <input
              value={rc}
              onChange={(e) => setRc(e.target.value)}
              placeholder="Enter identifier, plate, or subject"
              onKeyDown={(e) => e.key === 'Enter' && lookup()}
            />
            <button onClick={lookup} disabled={isLoading}>
              {isLoading ? 'Analyzing…' : 'Search'}
            </button>
            <button
              type="button"
              className="refresh-btn"
              onClick={resetState}
              disabled={isLoading}
              aria-label="Refresh"
              title="Refresh"
            >
              <span className="refresh-icon" aria-hidden="true">↻</span>
            </button>
          </div>

          {isLoading ? (
            <div className="loading-state">
              <div className="loading-bar" />
              <span>Scanning open-source signals…</span>
            </div>
          ) : status ? (
            <div className={`status ${status.includes('failed') || status.includes('issue') ? 'error' : 'success'}`}>
              <span className="dot" /> {status}
            </div>
          ) : null}
        </div>

        {result ? (
          <div className="result-card">
            <div className="result-head">
              <span>Signal</span>
              <span className="result-pill">Live</span>
            </div>
            <pre>{result}</pre>
          </div>
        ) : (
          !isLoading && <div className="empty-state">Vehicle details will appear here.</div>
        )}
      </div>

      {showScrollTop ? (
        <button type="button" className="scroll-top-btn" onClick={scrollToTop} aria-label="Scroll to top" title="Scroll to top">
          ↑
        </button>
      ) : null}
    </div>
  );
}

export default App;

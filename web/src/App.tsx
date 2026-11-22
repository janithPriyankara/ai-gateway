import { useEffect, useState } from 'react';
import { BrowserRouter, NavLink, Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom';
import * as api from './api';
import type { Me } from './api';
import { EventsProvider, SessionProvider, useEvents, useSession } from './session';
import { ErrorNotice, Loading } from './components/ui';
import {
  IconActivity, IconBot, IconCheckCircle, IconDiff, IconHome, IconLock, IconLogout, IconMenu, IconServer, IconShieldList, IconUsers, IconX,
} from './icons';
import LoginPage from './pages/Login';
import { InvitePage, SetupPage } from './pages/Register';
import OverviewPage from './pages/Overview';
import ServersPage from './pages/Servers';
import ServerDetailPage from './pages/ServerDetail';
import ClientsPage from './pages/Clients';
import ProfilesPage from './pages/Profiles';
import ApprovalsPage from './pages/Approvals';
import ToolChangesPage from './pages/ToolChanges';
import ActivityPage from './pages/Activity';
import SecurityPage from './pages/Security';
import UsersPage from './pages/Users';

type Boot =
  | { state: 'loading' }
  | { state: 'in'; me: Me }
  | { state: 'out'; setupRequired: boolean }
  | { state: 'error'; error: unknown };

export default function App() {
  return (
    <BrowserRouter basename="/admin">
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/setup" element={<SetupPage />} />
        <Route path="/invite" element={<InvitePage />} />
        <Route path="/*" element={<Protected />} />
      </Routes>
    </BrowserRouter>
  );
}

function Protected() {
  const [boot, setBoot] = useState<Boot>({ state: 'loading' });
  const location = useLocation();

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const me = await api.me();
        api.setCsrf(me.csrf);
        if (!cancelled) setBoot({ state: 'in', me });
      } catch (e) {
        if (e instanceof api.ApiError && e.status === 401) {
          let setupRequired = false;
          try {
            setupRequired = (await api.authStatus()).setup_required;
          } catch {
            /* fall through to login */
          }
          if (!cancelled) setBoot({ state: 'out', setupRequired });
        } else if (!cancelled) {
          setBoot({ state: 'error', error: e });
        }
      }
    })();
    api.setUnauthenticatedHandler(() => {
      const next = window.location.pathname + window.location.search;
      window.location.assign('/admin/login?next=' + encodeURIComponent(next));
    });
    return () => {
      cancelled = true;
      api.setUnauthenticatedHandler(null);
    };
  }, []);

  if (boot.state === 'loading') {
    return (
      <div className="auth-wrap">
        <Loading />
      </div>
    );
  }
  if (boot.state === 'error') {
    return (
      <div className="auth-wrap">
        <div className="card auth-card">
          <ErrorNotice error={boot.error} />
          <button type="button" onClick={() => window.location.reload()}>Try again</button>
        </div>
      </div>
    );
  }
  if (boot.state === 'out') {
    if (boot.setupRequired) return <Navigate to="/setup" replace />;
    const here = location.pathname === '/' ? '' : '/admin' + location.pathname + location.search;
    return <Navigate to={here ? `/login?next=${encodeURIComponent(here)}` : '/login'} replace />;
  }
  return (
    <SessionProvider me={boot.me}>
      <EventsProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<OverviewPage />} />
            <Route path="servers" element={<ServersPage />} />
            <Route path="servers/:id" element={<ServerDetailPage />} />
            <Route path="clients" element={<ClientsPage />} />
            <Route path="profiles" element={<ProfilesPage />} />
            <Route path="approvals" element={<ApprovalsPage />} />
            <Route path="tool-changes" element={<ToolChangesPage />} />
            <Route path="activity" element={<ActivityPage />} />
            <Route path="security" element={<SecurityPage />} />
            <Route path="users" element={<UsersPage />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </EventsProvider>
    </SessionProvider>
  );
}

function NotFound() {
  return (
    <div className="card">
      <h2>Page not found</h2>
      <p className="muted">This page does not exist.</p>
      <NavLink to="/">Go to the overview</NavLink>
    </div>
  );
}

const NAV = [
  { to: '/', label: 'Overview', icon: IconHome, end: true },
  { to: '/servers', label: 'Servers', icon: IconServer },
  { to: '/clients', label: 'AI tools', icon: IconBot },
  { to: '/profiles', label: 'Profiles', icon: IconShieldList },
  { to: '/approvals', label: 'Approvals', icon: IconCheckCircle, badge: true },
  { to: '/tool-changes', label: 'Tool changes', icon: IconDiff },
  { to: '/activity', label: 'Activity', icon: IconActivity },
  { to: '/security', label: 'Security', icon: IconLock },
  { to: '/users', label: 'Users', icon: IconUsers, admin: true },
];

function Layout() {
  const { me, can, signOut } = useSession();
  const { pendingCount } = useEvents();
  const [open, setOpen] = useState(false);
  const location = useLocation();
  useEffect(() => setOpen(false), [location.pathname]);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open]);

  return (
    <div className="app">
      <header className="topbar">
        <button type="button" className="ghost icon" onClick={() => setOpen(true)} aria-label="Open menu" aria-expanded={open}
          aria-controls="sidebar">
          <IconMenu />
        </button>
        <span className="brand" style={{ padding: 0 }}>
          <span className="brand-mark" aria-hidden="true">g</span> mcp-gateway
        </span>
        {pendingCount > 0 && (
          <NavLink to="/approvals" className="badge accent" style={{ marginLeft: 'auto' }}>
            {pendingCount} pending
          </NavLink>
        )}
      </header>
      {open && <div className="nav-backdrop" onClick={() => setOpen(false)} aria-hidden="true" />}
      <aside id="sidebar" className={`sidebar${open ? ' open' : ''}`} aria-label="Main navigation">
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <span className="brand">
            <span className="brand-mark" aria-hidden="true">g</span> mcp-gateway
          </span>
          {open && (
            <button type="button" className="ghost icon" onClick={() => setOpen(false)} aria-label="Close menu" autoFocus>
              <IconX size={16} />
            </button>
          )}
        </div>
        <nav className="nav">
          {NAV.filter((n) => !n.admin || can('admin')).map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end} className={({ isActive }) => (isActive ? 'active' : '')}>
              <n.icon />
              <span>{n.label}</span>
              {n.badge && pendingCount > 0 && (
                <span className="count" data-testid="pending-badge" aria-label={`${pendingCount} pending`}>
                  {pendingCount}
                </span>
              )}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="who">
            <strong>{me.name}</strong>
            <span className="muted small" data-testid="my-role">{roleLabel(me.role)}</span>
          </div>
          <button type="button" className="sm" onClick={() => void signOut()}>
            <IconLogout size={14} /> Sign out
          </button>
        </div>
      </aside>
      <main className="main" id="main">
        <Outlet />
      </main>
    </div>
  );
}

export function roleLabel(r: string): string {
  return r ? r.charAt(0).toUpperCase() + r.slice(1) : r;
}

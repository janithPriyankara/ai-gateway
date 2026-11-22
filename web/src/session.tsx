import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import * as api from './api';
import type { Me, Role } from './api';

interface SessionValue {
  me: Me;
  can: (min: Role) => boolean;
  signOut: () => Promise<void>;
}

const SessionCtx = createContext<SessionValue | null>(null);

export function SessionProvider({ me, children }: { me: Me; children: ReactNode }) {
  const signOut = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      window.location.assign('/admin/login');
    }
  }, []);
  const value = useMemo<SessionValue>(() => ({ me, can: (min) => api.atLeast(me.role, min), signOut }), [me, signOut]);
  return <SessionCtx.Provider value={value}>{children}</SessionCtx.Provider>;
}

export function useSession(): SessionValue {
  const v = useContext(SessionCtx);
  if (!v) throw new Error('useSession outside SessionProvider');
  return v;
}

// --- live events (SSE) ---

export type GatewayEventType = 'approval.created' | 'approval.decided' | 'audit.event' | 'server.health' | 'config.changed';
type Handler = (data: unknown) => void;

interface EventsValue {
  subscribe: (type: GatewayEventType | 'open', fn: Handler) => () => void;
  pendingCount: number;
  connected: boolean;
}

const EventsCtx = createContext<EventsValue | null>(null);
const TYPES: GatewayEventType[] = ['approval.created', 'approval.decided', 'audit.event', 'server.health', 'config.changed'];

export function EventsProvider({ children }: { children: ReactNode }) {
  const handlers = useRef(new Map<string, Set<Handler>>());
  const [pendingCount, setPendingCount] = useState(0);
  const [connected, setConnected] = useState(false);

  const emit = useCallback((type: string, data: unknown) => {
    handlers.current.get(type)?.forEach((fn) => {
      try {
        fn(data);
      } catch {
        /* a broken subscriber must not break the stream */
      }
    });
  }, []);

  const refreshPending = useCallback(async () => {
    try {
      const list = await api.listApprovals('pending');
      setPendingCount(list.length);
    } catch {
      /* ignore: the badge is best-effort */
    }
  }, []);

  useEffect(() => {
    void refreshPending();
    let es: EventSource | null = null;
    let retry: number | undefined;
    let closed = false;
    const connect = () => {
      es = new EventSource(api.EVENTS_URL, { withCredentials: true });
      es.onopen = () => {
        setConnected(true);
        void refreshPending();
        emit('open', null);
      };
      es.onerror = () => {
        setConnected(false);
        if (es && es.readyState === EventSource.CLOSED && !closed) {
          es.close();
          retry = window.setTimeout(connect, 3000);
        }
      };
      for (const t of TYPES) {
        es.addEventListener(t, (ev) => {
          let data: unknown = null;
          try {
            data = JSON.parse((ev as MessageEvent<string>).data);
          } catch {
            data = null;
          }
          if (t === 'approval.created' || t === 'approval.decided') void refreshPending();
          emit(t, data);
        });
      }
    };
    connect();
    return () => {
      closed = true;
      window.clearTimeout(retry);
      es?.close();
    };
  }, [emit, refreshPending]);

  const subscribe = useCallback((type: string, fn: Handler) => {
    let set = handlers.current.get(type);
    if (!set) {
      set = new Set();
      handlers.current.set(type, set);
    }
    set.add(fn);
    return () => {
      set?.delete(fn);
    };
  }, []);

  const value = useMemo(() => ({ subscribe, pendingCount, connected }), [subscribe, pendingCount, connected]);
  return <EventsCtx.Provider value={value}>{children}</EventsCtx.Provider>;
}

export function useEvents(): EventsValue {
  const v = useContext(EventsCtx);
  if (!v) throw new Error('useEvents outside EventsProvider');
  return v;
}

/** Calls fn whenever one of the given live events arrives (and when the stream reconnects). */
export function useLiveRefresh(types: GatewayEventType[], fn: () => void) {
  const { subscribe } = useEvents();
  const ref = useRef(fn);
  ref.current = fn;
  const key = types.join(',');
  useEffect(() => {
    const offs = [...key.split(','), 'open'].map((t) => subscribe(t as GatewayEventType, () => ref.current()));
    return () => offs.forEach((off) => off());
  }, [key, subscribe]);
}

// Small inline SVG icon set (stroke icons, 24px grid).
import type { ReactElement } from 'react';

type P = { size?: number };

function Svg({ size = 18, children }: P & { children: ReactElement | ReactElement[] }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      {children}
    </svg>
  );
}

export const IconHome = (p: P) => <Svg {...p}><path d="M3 11l9-7 9 7" /><path d="M5 10v10h14V10" /></Svg>;
export const IconServer = (p: P) => (
  <Svg {...p}><rect x="3" y="4" width="18" height="7" rx="2" /><rect x="3" y="13" width="18" height="7" rx="2" /><path d="M7 7.5h.01M7 16.5h.01" /></Svg>
);
export const IconBot = (p: P) => (
  <Svg {...p}><rect x="4" y="8" width="16" height="12" rx="3" /><path d="M12 4v4M9 13h.01M15 13h.01M9 17h6" /></Svg>
);
export const IconShieldList = (p: P) => (
  <Svg {...p}><path d="M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6z" /><path d="M9 10h6M9 14h4" /></Svg>
);
export const IconCheckCircle = (p: P) => <Svg {...p}><circle cx="12" cy="12" r="9" /><path d="M8 12l3 3 5-6" /></Svg>;
export const IconDiff = (p: P) => (
  <Svg {...p}><path d="M6 3v12M18 9v12" /><circle cx="6" cy="18" r="3" /><circle cx="18" cy="6" r="3" /><path d="M12 6h3M12 18H9" /></Svg>
);
export const IconActivity = (p: P) => <Svg {...p}><path d="M3 12h4l3-8 4 16 3-8h4" /></Svg>;
export const IconLock = (p: P) => <Svg {...p}><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 018 0v3" /></Svg>;
export const IconUsers = (p: P) => (
  <Svg {...p}><circle cx="9" cy="8" r="3.5" /><path d="M2.5 20c.8-3.4 3.4-5.5 6.5-5.5s5.7 2.1 6.5 5.5" /><path d="M16 4.5a3.5 3.5 0 010 7M18 14.8c1.8.8 3 2.6 3.5 5.2" /></Svg>
);
export const IconMenu = (p: P) => <Svg {...p}><path d="M4 6h16M4 12h16M4 18h16" /></Svg>;
export const IconX = (p: P) => <Svg {...p}><path d="M6 6l12 12M18 6L6 18" /></Svg>;
export const IconPlus = (p: P) => <Svg {...p}><path d="M12 5v14M5 12h14" /></Svg>;
export const IconTrash = (p: P) => <Svg {...p}><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3" /></Svg>;
export const IconUp = (p: P) => <Svg {...p}><path d="M12 19V5M6 11l6-6 6 6" /></Svg>;
export const IconDown = (p: P) => <Svg {...p}><path d="M12 5v14M6 13l6 6 6-6" /></Svg>;
export const IconCopy = (p: P) => <Svg {...p}><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a1 1 0 011-1h10" /></Svg>;
export const IconAlert = (p: P) => <Svg {...p}><path d="M12 3l9.5 17h-19z" /><path d="M12 10v4M12 17h.01" /></Svg>;
export const IconLogout = (p: P) => <Svg {...p}><path d="M15 4h4v16h-4M10 8l-4 4 4 4M6 12h10" /></Svg>;
export const IconKey = (p: P) => <Svg {...p}><circle cx="8" cy="14" r="4" /><path d="M11 11l9-9M17 5l3 3M14 8l2 2" /></Svg>;
export const IconChevron = (p: P) => <Svg {...p}><path d="M9 6l6 6-6 6" /></Svg>;

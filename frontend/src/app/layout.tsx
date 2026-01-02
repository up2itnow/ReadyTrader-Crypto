import type { Metadata, Viewport } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "ReadyTrader | Institutional AI Trading",
  description: "High-performance AI agent trading dashboard with mobile trade approvals, real-time market data, and comprehensive risk management.",
  manifest: "/manifest.json",
  appleWebApp: {
    capable: true,
    statusBarStyle: "black-translucent",
    title: "ReadyTrader",
  },
  formatDetection: {
    telephone: false,
  },
  keywords: ["crypto", "trading", "AI", "MCP", "agent", "defi", "cex"],
  authors: [{ name: "ReadyTrader Team" }],
  openGraph: {
    title: "ReadyTrader | Institutional AI Trading",
    description: "High-performance AI agent trading dashboard",
    type: "website",
  },
};

export const viewport: Viewport = {
  themeColor: "#00f2ff",
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
  userScalable: true,
  viewportFit: "cover",
};

// Navigation items configuration
const navItems = [
  { href: "/", label: "Dashboard", icon: "📊" },
  { href: "/strategy", label: "Strategy", icon: "🧠" },
  { href: "/history", label: "History", icon: "📜" },
  { href: "/settings", label: "Settings", icon: "⚙️" },
];

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link 
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" 
          rel="stylesheet" 
        />
      </head>
      <body>
        {/* Skip to main content link for accessibility */}
        <a 
          href="#main-content" 
          className="sr-only"
          style={{
            position: 'absolute',
            left: '-9999px',
            zIndex: 999,
            padding: '1em',
            background: 'var(--primary)',
            color: 'black',
            textDecoration: 'none',
          }}
        >
          Skip to main content
        </a>

        <div className="layout-root">
          {/* Sidebar Navigation */}
          <aside className="sidebar" role="navigation" aria-label="Main navigation">
            <div className="logo-container">
              <Link href="/" aria-label="ReadyTrader Home">
                <span className="logo-text">READY<span>TRADER</span></span>
              </Link>
            </div>
            
            <nav className="main-nav" aria-label="Primary">
              {navItems.map((item) => (
                <Link 
                  key={item.href}
                  href={item.href} 
                  className="nav-item"
                  aria-current={item.href === "/" ? "page" : undefined}
                >
                  <span role="img" aria-hidden="true">{item.icon}</span>
                  {item.label}
                </Link>
              ))}
            </nav>

            {/* Version info at bottom */}
            <div style={{ 
              marginTop: 'auto', 
              padding: '24px', 
              fontSize: '11px', 
              color: 'var(--muted)' 
            }}>
              <div>v0.2.0</div>
              <div style={{ marginTop: 4 }}>
                <a 
                  href="https://github.com/up2itnow/ReadyTrader-Crypto" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  style={{ color: 'var(--primary)', textDecoration: 'none' }}
                >
                  GitHub
                </a>
                {" • "}
                <a 
                  href="/docs" 
                  style={{ color: 'var(--muted)', textDecoration: 'none' }}
                >
                  Docs
                </a>
              </div>
            </div>
          </aside>

          {/* Main Content Area */}
          <main className="content" id="main-content" role="main">
            {/* Top Bar */}
            <header className="top-bar" role="banner">
              {/* Mobile menu toggle - controlled by CSS/JS in page component */}
              <button 
                className="mobile-menu-toggle" 
                aria-label="Toggle navigation menu"
                aria-expanded="false"
                aria-controls="sidebar"
              >
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="3" y1="6" x2="21" y2="6" />
                  <line x1="3" y1="12" x2="21" y2="12" />
                  <line x1="3" y1="18" x2="21" y2="18" />
                </svg>
              </button>

              {/* Status Indicators */}
              <div className="status-indicators" role="status" aria-live="polite">
                <span className="status-pill paper" aria-label="Paper trading mode active">
                  <span role="img" aria-hidden="true">📝</span>
                  Paper Mode
                </span>
              </div>

              {/* User Profile / Agent Info */}
              <div className="user-profile" aria-label="Current agent">
                <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span 
                    style={{ 
                      width: 8, 
                      height: 8, 
                      borderRadius: '50%', 
                      background: 'var(--success)',
                      boxShadow: '0 0 8px var(--success)'
                    }}
                    aria-hidden="true"
                  />
                  Agent Zero
                </span>
              </div>
            </header>

            {/* Page Content */}
            {children}

            {/* Footer */}
            <footer 
              style={{ 
                padding: '24px 40px', 
                borderTop: '1px solid var(--card-border)',
                fontSize: '12px',
                color: 'var(--muted)',
                display: 'flex',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: 16
              }}
              role="contentinfo"
            >
              <div>
                © 2025 ReadyTrader-Crypto. MIT License.
              </div>
              <div style={{ display: 'flex', gap: 16 }}>
                <a 
                  href="/disclaimer" 
                  style={{ color: 'var(--muted)', textDecoration: 'none' }}
                >
                  Disclaimer
                </a>
                <a 
                  href="/security" 
                  style={{ color: 'var(--muted)', textDecoration: 'none' }}
                >
                  Security
                </a>
                <a 
                  href="https://github.com/up2itnow/ReadyTrader-Crypto/issues" 
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: 'var(--muted)', textDecoration: 'none' }}
                >
                  Report Issue
                </a>
              </div>
            </footer>
          </main>
        </div>

        {/* Service Worker Registration Script */}
        <script
          dangerouslySetInnerHTML={{
            __html: `
              if ('serviceWorker' in navigator) {
                window.addEventListener('load', function() {
                  navigator.serviceWorker.register('/sw.js').catch(function(err) {
                    console.log('ServiceWorker registration failed:', err);
                  });
                });
              }
            `,
          }}
        />
      </body>
    </html>
  );
}

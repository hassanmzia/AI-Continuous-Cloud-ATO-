import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Dashboard from './pages/Dashboard';
import ControlCockpit from './pages/ControlCockpit';
import EvidenceExplorer from './pages/EvidenceExplorer';
import DriftTimeline from './pages/DriftTimeline';
import Approvals from './pages/Approvals';
import Reports from './pages/Reports';

const queryClient = new QueryClient();

const navItems = [
  { path: '/', label: 'Dashboard' },
  { path: '/controls', label: 'Controls' },
  { path: '/evidence', label: 'Evidence' },
  { path: '/drift', label: 'Drift' },
  { path: '/approvals', label: 'Approvals' },
  { path: '/reports', label: 'Reports' },
];

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div style={{ display: 'flex', minHeight: '100vh', fontFamily: 'system-ui, sans-serif' }}>
          {/* Sidebar Navigation */}
          <nav style={{
            width: 220,
            background: '#1a1f36',
            color: '#fff',
            padding: '20px 0',
            display: 'flex',
            flexDirection: 'column',
          }}>
            <div style={{ padding: '0 20px 20px', borderBottom: '1px solid #2d3352' }}>
              <h2 style={{ margin: 0, fontSize: 16, fontWeight: 700 }}>AI Continuous ATO</h2>
              <p style={{ margin: '4px 0 0', fontSize: 11, color: '#8b92a5' }}>Multi-Cloud Compliance</p>
            </div>
            <div style={{ padding: '12px 0' }}>
              {navItems.map(item => (
                <NavLink
                  key={item.path}
                  to={item.path}
                  style={({ isActive }) => ({
                    display: 'block',
                    padding: '10px 20px',
                    color: isActive ? '#fff' : '#8b92a5',
                    background: isActive ? '#2d3352' : 'transparent',
                    textDecoration: 'none',
                    fontSize: 14,
                    borderLeft: isActive ? '3px solid #635bff' : '3px solid transparent',
                  })}
                >
                  {item.label}
                </NavLink>
              ))}
            </div>
          </nav>

          {/* Main Content */}
          <main style={{ flex: 1, background: '#f6f8fa', padding: 24 }}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/controls" element={<ControlCockpit />} />
              <Route path="/evidence" element={<EvidenceExplorer />} />
              <Route path="/drift" element={<DriftTimeline />} />
              <Route path="/approvals" element={<Approvals />} />
              <Route path="/reports" element={<Reports />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

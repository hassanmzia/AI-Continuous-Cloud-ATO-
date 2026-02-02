/**
 * Executive Compliance Dashboard
 *
 * Shows:
 * - Overall compliance score (gauge)
 * - Control status breakdown (pass/fail/partial)
 * - Drift events count
 * - Open POA&M items
 * - Recent compliance runs
 * - Per-provider compliance status
 */

import { useQuery } from '@tanstack/react-query';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

interface ComplianceRun {
  id: string;
  system: string;
  status: string;
  overall_score: number | null;
  trigger: string;
  created_at: string;
  summary: Record<string, number>;
}

function StatCard({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div style={{
      background: '#fff',
      borderRadius: 8,
      padding: '20px 24px',
      boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
      borderLeft: `4px solid ${color}`,
    }}>
      <div style={{ fontSize: 13, color: '#6b7280', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, color: '#1a1f36' }}>{value}</div>
    </div>
  );
}

function ScoreGauge({ score }: { score: number }) {
  const color = score >= 90 ? '#22c55e' : score >= 70 ? '#eab308' : score >= 50 ? '#f97316' : '#ef4444';
  return (
    <div style={{
      background: '#fff',
      borderRadius: 8,
      padding: 24,
      boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
      textAlign: 'center',
    }}>
      <div style={{ fontSize: 13, color: '#6b7280', marginBottom: 12 }}>Compliance Score</div>
      <div style={{
        width: 120, height: 120, borderRadius: '50%',
        border: `8px solid ${color}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        margin: '0 auto',
      }}>
        <span style={{ fontSize: 32, fontWeight: 700, color }}>{score.toFixed(0)}%</span>
      </div>
      <div style={{ marginTop: 8, fontSize: 12, color: '#6b7280' }}>
        {score >= 90 ? 'Strong' : score >= 70 ? 'Moderate' : score >= 50 ? 'Needs Improvement' : 'At Risk'}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { data: runs, isLoading } = useQuery<{ results: ComplianceRun[] }>({
    queryKey: ['runs'],
    queryFn: () => fetch(`${API_URL}/runs/?ordering=-created_at&page_size=10`).then(r => r.json()),
    refetchInterval: 30000,
  });

  const latestRun = runs?.results?.[0];
  const summary = latestRun?.summary || {};
  const score = latestRun?.overall_score ?? 0;

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24, color: '#1a1f36' }}>
        Compliance Dashboard
      </h1>

      {/* Score + Stats Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', gap: 24, marginBottom: 24 }}>
        <ScoreGauge score={score} />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
          <StatCard label="Controls Passing" value={summary.passed ?? '—'} color="#22c55e" />
          <StatCard label="Controls Failing" value={summary.failed ?? '—'} color="#ef4444" />
          <StatCard label="Partial" value={summary.partial ?? '—'} color="#f97316" />
          <StatCard label="Manual Review" value={summary.manual_review ?? '—'} color="#8b5cf6" />
        </div>
      </div>

      {/* Recent Runs */}
      <div style={{
        background: '#fff', borderRadius: 8, padding: 24,
        boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
      }}>
        <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>Recent Compliance Runs</h2>
        {isLoading ? (
          <p style={{ color: '#6b7280' }}>Loading...</p>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 14 }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #e5e7eb' }}>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Run ID</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Status</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Score</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Trigger</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Date</th>
              </tr>
            </thead>
            <tbody>
              {runs?.results?.map((run) => (
                <tr key={run.id} style={{ borderBottom: '1px solid #f3f4f6' }}>
                  <td style={{ padding: '10px 12px', fontFamily: 'monospace', fontSize: 12 }}>
                    {run.id.slice(0, 8)}
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <StatusBadge status={run.status} />
                  </td>
                  <td style={{ padding: '10px 12px', fontWeight: 600 }}>
                    {run.overall_score != null ? `${run.overall_score.toFixed(1)}%` : '—'}
                  </td>
                  <td style={{ padding: '10px 12px', color: '#6b7280' }}>{run.trigger}</td>
                  <td style={{ padding: '10px 12px', color: '#6b7280' }}>
                    {new Date(run.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, { bg: string; text: string }> = {
    completed: { bg: '#dcfce7', text: '#166534' },
    running: { bg: '#dbeafe', text: '#1e40af' },
    pending: { bg: '#fef3c7', text: '#92400e' },
    failed: { bg: '#fecaca', text: '#991b1b' },
    awaiting_approval: { bg: '#f3e8ff', text: '#6b21a8' },
  };
  const c = colors[status] || { bg: '#f3f4f6', text: '#374151' };
  return (
    <span style={{
      padding: '2px 8px', borderRadius: 4, fontSize: 12, fontWeight: 500,
      background: c.bg, color: c.text,
    }}>
      {status}
    </span>
  );
}

/**
 * Reports — Generated compliance reports viewer.
 *
 * Features:
 * - ConMon summary
 * - SSP delta suggestions
 * - Executive summary
 * - SAR evidence bundle manifest
 * - Control family breakdown
 */

import { useQuery } from '@tanstack/react-query';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

interface ComplianceRun {
  id: string;
  status: string;
  overall_score: number | null;
  summary: Record<string, number>;
  created_at: string;
}

export default function Reports() {
  const { data: runs } = useQuery<{ results: ComplianceRun[] }>({
    queryKey: ['runs-for-reports'],
    queryFn: () => fetch(`${API_URL}/runs/?ordering=-created_at&status=completed&page_size=5`).then(r => r.json()),
  });

  const latestRun = runs?.results?.[0];

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24, color: '#1a1f36' }}>
        Compliance Reports
      </h1>

      {/* Report Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20, marginBottom: 24 }}>
        <ReportCard
          title="ConMon Summary"
          description="Continuous Monitoring report with control status, drift events, STIG findings, and evidence freshness."
          icon="C"
          available={!!latestRun}
        />
        <ReportCard
          title="SSP Delta"
          description="Suggested updates to System Security Plan implementation statements based on detected gaps."
          icon="S"
          available={!!latestRun}
        />
        <ReportCard
          title="Executive Summary"
          description="High-level compliance posture overview with key metrics and top risks."
          icon="E"
          available={!!latestRun}
        />
        <ReportCard
          title="SAR Evidence Bundle"
          description="Security Assessment Report evidence package with artifact manifest and hashes."
          icon="R"
          available={!!latestRun}
        />
        <ReportCard
          title="Family Breakdown"
          description="Per-control-family compliance scores and pass/fail distribution."
          icon="F"
          available={!!latestRun}
        />
        <ReportCard
          title="POA&M Export"
          description="Plan of Action & Milestones export with all open items, milestones, and owners."
          icon="P"
          available={!!latestRun}
        />
      </div>

      {/* Latest Run Summary */}
      {latestRun && (
        <div style={{
          background: '#fff', borderRadius: 8, padding: 24,
          boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
        }}>
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>
            Latest Completed Run
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
            <MetricBox label="Run ID" value={latestRun.id.slice(0, 8)} />
            <MetricBox label="Score" value={`${latestRun.overall_score?.toFixed(1) ?? '—'}%`} />
            <MetricBox label="Controls Assessed" value={latestRun.summary?.total_controls ?? '—'} />
            <MetricBox label="Date" value={new Date(latestRun.created_at).toLocaleDateString()} />
          </div>
        </div>
      )}

      {!latestRun && (
        <div style={{
          background: '#fff', borderRadius: 8, padding: 40, textAlign: 'center',
          boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
        }}>
          <p style={{ color: '#6b7280', fontSize: 16 }}>
            No completed compliance runs found. Trigger a run to generate reports.
          </p>
        </div>
      )}
    </div>
  );
}

function ReportCard({ title, description, icon, available }: {
  title: string; description: string; icon: string; available: boolean;
}) {
  return (
    <div style={{
      background: '#fff', borderRadius: 8, padding: 20,
      boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
      opacity: available ? 1 : 0.6,
      cursor: available ? 'pointer' : 'default',
      transition: 'box-shadow 0.2s',
    }}>
      <div style={{
        width: 36, height: 36, borderRadius: 8,
        background: '#eff6ff', color: '#1e40af',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontWeight: 700, fontSize: 16, marginBottom: 12,
      }}>
        {icon}
      </div>
      <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 6, color: '#1a1f36' }}>{title}</h3>
      <p style={{ fontSize: 12, color: '#6b7280', lineHeight: 1.5, margin: 0 }}>{description}</p>
      {available && (
        <div style={{ marginTop: 12, fontSize: 12, color: '#635bff', fontWeight: 500 }}>
          View Report
        </div>
      )}
    </div>
  );
}

function MetricBox({ label, value }: { label: string; value: string | number }) {
  return (
    <div style={{ padding: '12px 16px', background: '#f9fafb', borderRadius: 6 }}>
      <div style={{ fontSize: 11, color: '#6b7280', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 600, color: '#1a1f36' }}>{value}</div>
    </div>
  );
}

/**
 * Control Cockpit — Per-control compliance status with evidence and assessment details.
 *
 * Features:
 * - Filterable/searchable control list
 * - Status breakdown by framework
 * - Control detail view with evidence citations, confidence, rationale
 * - Cross-framework mapping view (NIST <-> STIG via CCI)
 */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

interface Assessment {
  id: string;
  control_id: string;
  framework: string;
  status: string;
  confidence: number;
  rationale: string;
  provider: string;
  evidence_sufficiency_score: number | null;
  contradictions_detected: unknown[];
  created_at: string;
}

const statusColors: Record<string, string> = {
  pass: '#22c55e',
  fail: '#ef4444',
  partial: '#f97316',
  not_applicable: '#9ca3af',
  manual_review_required: '#8b5cf6',
};

export default function ControlCockpit() {
  const [frameworkFilter, setFrameworkFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [search, setSearch] = useState('');

  const params = new URLSearchParams();
  if (frameworkFilter) params.set('framework', frameworkFilter);
  if (statusFilter) params.set('status', statusFilter);
  if (search) params.set('search', search);

  const { data, isLoading } = useQuery<{ results: Assessment[] }>({
    queryKey: ['assessments', frameworkFilter, statusFilter, search],
    queryFn: () => fetch(`${API_URL}/assessments/?${params}`).then(r => r.json()),
  });

  const assessments = data?.results || [];

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24, color: '#1a1f36' }}>
        Control Cockpit
      </h1>

      {/* Filters */}
      <div style={{
        display: 'flex', gap: 12, marginBottom: 20,
        background: '#fff', padding: 16, borderRadius: 8,
        boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
      }}>
        <select
          value={frameworkFilter}
          onChange={e => setFrameworkFilter(e.target.value)}
          style={{ padding: '6px 12px', borderRadius: 4, border: '1px solid #d1d5db', fontSize: 14 }}
        >
          <option value="">All Frameworks</option>
          <option value="fedramp">FedRAMP</option>
          <option value="nist_800_53_r5">NIST 800-53</option>
          <option value="rmf">RMF</option>
          <option value="stig">STIG</option>
        </select>

        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          style={{ padding: '6px 12px', borderRadius: 4, border: '1px solid #d1d5db', fontSize: 14 }}
        >
          <option value="">All Statuses</option>
          <option value="pass">Pass</option>
          <option value="fail">Fail</option>
          <option value="partial">Partial</option>
          <option value="manual_review_required">Manual Review</option>
        </select>

        <input
          type="text"
          placeholder="Search controls..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ padding: '6px 12px', borderRadius: 4, border: '1px solid #d1d5db', fontSize: 14, flex: 1 }}
        />
      </div>

      {/* Control List */}
      <div style={{
        background: '#fff', borderRadius: 8, padding: 24,
        boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
      }}>
        {isLoading ? (
          <p style={{ color: '#6b7280' }}>Loading assessments...</p>
        ) : assessments.length === 0 ? (
          <p style={{ color: '#6b7280' }}>No assessments found. Trigger a compliance run first.</p>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 14 }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #e5e7eb' }}>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Control</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Framework</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Status</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Confidence</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Provider</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Sufficiency</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Rationale</th>
              </tr>
            </thead>
            <tbody>
              {assessments.map((a) => (
                <tr key={a.id} style={{ borderBottom: '1px solid #f3f4f6' }}>
                  <td style={{ padding: '10px 12px', fontWeight: 600, fontFamily: 'monospace' }}>
                    {a.control_id}
                  </td>
                  <td style={{ padding: '10px 12px', color: '#6b7280' }}>{a.framework}</td>
                  <td style={{ padding: '10px 12px' }}>
                    <span style={{
                      display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
                      background: statusColors[a.status] || '#9ca3af',
                      marginRight: 6,
                    }} />
                    {a.status}
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    {(a.confidence * 100).toFixed(0)}%
                  </td>
                  <td style={{ padding: '10px 12px', color: '#6b7280' }}>{a.provider || '—'}</td>
                  <td style={{ padding: '10px 12px' }}>
                    {a.evidence_sufficiency_score != null
                      ? `${(a.evidence_sufficiency_score * 100).toFixed(0)}%`
                      : '—'}
                  </td>
                  <td style={{
                    padding: '10px 12px', color: '#6b7280', maxWidth: 300,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>
                    {a.rationale || '—'}
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

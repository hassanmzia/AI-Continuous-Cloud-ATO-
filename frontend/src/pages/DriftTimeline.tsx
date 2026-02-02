/**
 * Drift Timeline — Configuration drift events timeline with severity and attribution.
 *
 * Features:
 * - Chronological drift event display
 * - Severity color coding
 * - Changed-by attribution
 * - Affected controls mapping
 * - Filter by provider/severity/resolved status
 */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

interface DriftEvent {
  id: string;
  system: string;
  provider: string;
  resource_type: string;
  resource_id: string;
  field_path: string;
  baseline_value: unknown;
  current_value: unknown;
  changed_by: string;
  changed_at: string;
  severity: string;
  affected_controls: string[];
  resolved: boolean;
  created_at: string;
}

const severityColors: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: '#fef2f2', text: '#991b1b', border: '#ef4444' },
  high: { bg: '#fff7ed', text: '#9a3412', border: '#f97316' },
  moderate: { bg: '#fffbeb', text: '#92400e', border: '#eab308' },
  medium: { bg: '#fffbeb', text: '#92400e', border: '#eab308' },
  low: { bg: '#f0fdf4', text: '#166534', border: '#22c55e' },
  info: { bg: '#eff6ff', text: '#1e40af', border: '#3b82f6' },
};

export default function DriftTimeline() {
  const [severityFilter, setSeverityFilter] = useState('');
  const [resolvedFilter, setResolvedFilter] = useState('');

  const params = new URLSearchParams();
  if (severityFilter) params.set('severity', severityFilter);
  if (resolvedFilter) params.set('resolved', resolvedFilter);
  params.set('ordering', '-created_at');

  const { data, isLoading } = useQuery<{ results: DriftEvent[] }>({
    queryKey: ['drift', severityFilter, resolvedFilter],
    queryFn: () => fetch(`${API_URL}/drift-events/?${params}`).then(r => r.json()),
  });

  const events = data?.results || [];

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24, color: '#1a1f36' }}>
        Drift Timeline
      </h1>

      {/* Filters */}
      <div style={{
        display: 'flex', gap: 12, marginBottom: 20,
        background: '#fff', padding: 16, borderRadius: 8,
        boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
      }}>
        <select
          value={severityFilter}
          onChange={e => setSeverityFilter(e.target.value)}
          style={{ padding: '6px 12px', borderRadius: 4, border: '1px solid #d1d5db', fontSize: 14 }}
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="moderate">Moderate</option>
          <option value="low">Low</option>
        </select>

        <select
          value={resolvedFilter}
          onChange={e => setResolvedFilter(e.target.value)}
          style={{ padding: '6px 12px', borderRadius: 4, border: '1px solid #d1d5db', fontSize: 14 }}
        >
          <option value="">All Status</option>
          <option value="false">Unresolved</option>
          <option value="true">Resolved</option>
        </select>
      </div>

      {/* Timeline */}
      <div style={{ position: 'relative', paddingLeft: 40 }}>
        {/* Vertical line */}
        <div style={{
          position: 'absolute', left: 15, top: 0, bottom: 0,
          width: 2, background: '#e5e7eb',
        }} />

        {isLoading ? (
          <p style={{ color: '#6b7280', marginLeft: 20 }}>Loading drift events...</p>
        ) : events.length === 0 ? (
          <p style={{ color: '#6b7280', marginLeft: 20 }}>No drift events detected.</p>
        ) : (
          events.map((event) => {
            const sc = severityColors[event.severity] || severityColors.info;
            return (
              <div key={event.id} style={{ marginBottom: 16, position: 'relative' }}>
                {/* Timeline dot */}
                <div style={{
                  position: 'absolute', left: -33, top: 16,
                  width: 12, height: 12, borderRadius: '50%',
                  background: sc.border, border: '2px solid #fff',
                  boxShadow: '0 0 0 2px ' + sc.border,
                }} />

                {/* Event card */}
                <div style={{
                  background: sc.bg, borderRadius: 8, padding: 16,
                  borderLeft: `4px solid ${sc.border}`,
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                    <span style={{ fontWeight: 600, color: sc.text }}>
                      {event.severity.toUpperCase()} — {event.resource_type}
                    </span>
                    <span style={{ fontSize: 12, color: '#6b7280' }}>
                      {new Date(event.created_at).toLocaleString()}
                    </span>
                  </div>
                  <div style={{ fontSize: 13, color: '#374151', marginBottom: 8 }}>
                    <strong>Resource:</strong> {event.resource_id}
                  </div>
                  <div style={{ fontSize: 13, color: '#374151', marginBottom: 8 }}>
                    <strong>Field:</strong> {event.field_path}
                  </div>
                  {event.changed_by && (
                    <div style={{ fontSize: 13, color: '#374151', marginBottom: 8 }}>
                      <strong>Changed by:</strong> {event.changed_by}
                    </div>
                  )}
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {event.affected_controls?.map(ctrl => (
                      <span key={ctrl} style={{
                        padding: '1px 6px', borderRadius: 3,
                        background: '#fff', fontSize: 11, border: '1px solid #d1d5db',
                      }}>
                        {ctrl}
                      </span>
                    ))}
                    {event.resolved && (
                      <span style={{
                        padding: '1px 6px', borderRadius: 3,
                        background: '#dcfce7', color: '#166534', fontSize: 11,
                      }}>
                        Resolved
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

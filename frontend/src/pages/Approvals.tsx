/**
 * Approvals — Human-in-the-loop approval queue for remediation actions.
 *
 * Features:
 * - List pending approval requests
 * - Show proposed action details (POA&M, tickets, PRs)
 * - Approve/reject with notes
 * - Audit trail of past decisions
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

interface ApprovalRequest {
  id: string;
  run: string;
  system: string;
  action_type: string;
  action_payload: Record<string, unknown>;
  affected_controls: string[];
  severity: string;
  status: string;
  requested_by_agent: string;
  reviewed_by: string;
  reviewed_at: string | null;
  review_notes: string;
  created_at: string;
}

export default function Approvals() {
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [reviewNotes, setReviewNotes] = useState('');

  const { data, isLoading } = useQuery<{ results: ApprovalRequest[] }>({
    queryKey: ['approvals'],
    queryFn: () => fetch(`${API_URL}/approvals/?ordering=-created_at`).then(r => r.json()),
    refetchInterval: 15000,
  });

  const reviewMutation = useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'approved' | 'rejected' }) =>
      fetch(`${API_URL}/approvals/${id}/review/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: action,
          reviewed_by: 'admin@example.com',
          review_notes: reviewNotes,
        }),
      }).then(r => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['approvals'] });
      setSelectedId(null);
      setReviewNotes('');
    },
  });

  const approvals = data?.results || [];
  const pending = approvals.filter(a => a.status === 'pending');
  const reviewed = approvals.filter(a => a.status !== 'pending');

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24, color: '#1a1f36' }}>
        Approval Queue
      </h1>

      {/* Pending Approvals */}
      <div style={{
        background: '#fff', borderRadius: 8, padding: 24, marginBottom: 24,
        boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
      }}>
        <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>
          Pending ({pending.length})
        </h2>

        {isLoading ? (
          <p style={{ color: '#6b7280' }}>Loading...</p>
        ) : pending.length === 0 ? (
          <p style={{ color: '#6b7280' }}>No pending approvals.</p>
        ) : (
          pending.map(approval => (
            <div key={approval.id} style={{
              border: '1px solid #e5e7eb', borderRadius: 8, padding: 16, marginBottom: 12,
              borderLeft: `4px solid ${approval.severity === 'critical' ? '#ef4444' : '#f97316'}`,
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <span style={{ fontWeight: 600 }}>
                  {approval.action_type} — {approval.severity.toUpperCase()}
                </span>
                <span style={{ fontSize: 12, color: '#6b7280' }}>
                  {new Date(approval.created_at).toLocaleString()}
                </span>
              </div>

              <div style={{ fontSize: 13, color: '#374151', marginBottom: 8 }}>
                <strong>Requested by:</strong> {approval.requested_by_agent}
              </div>

              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
                {approval.affected_controls?.map(ctrl => (
                  <span key={ctrl} style={{
                    padding: '1px 6px', borderRadius: 3, background: '#fef3c7',
                    fontSize: 11, color: '#92400e',
                  }}>
                    {ctrl}
                  </span>
                ))}
              </div>

              {selectedId === approval.id ? (
                <div>
                  <textarea
                    placeholder="Review notes (optional)..."
                    value={reviewNotes}
                    onChange={e => setReviewNotes(e.target.value)}
                    style={{
                      width: '100%', padding: 8, borderRadius: 4,
                      border: '1px solid #d1d5db', fontSize: 13, marginBottom: 8,
                      minHeight: 60,
                    }}
                  />
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button
                      onClick={() => reviewMutation.mutate({ id: approval.id, action: 'approved' })}
                      style={{
                        padding: '6px 16px', borderRadius: 4, border: 'none',
                        background: '#22c55e', color: '#fff', fontSize: 13, cursor: 'pointer',
                      }}
                    >
                      Approve
                    </button>
                    <button
                      onClick={() => reviewMutation.mutate({ id: approval.id, action: 'rejected' })}
                      style={{
                        padding: '6px 16px', borderRadius: 4, border: 'none',
                        background: '#ef4444', color: '#fff', fontSize: 13, cursor: 'pointer',
                      }}
                    >
                      Reject
                    </button>
                    <button
                      onClick={() => { setSelectedId(null); setReviewNotes(''); }}
                      style={{
                        padding: '6px 16px', borderRadius: 4, border: '1px solid #d1d5db',
                        background: '#fff', fontSize: 13, cursor: 'pointer',
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  onClick={() => setSelectedId(approval.id)}
                  style={{
                    padding: '6px 16px', borderRadius: 4, border: '1px solid #d1d5db',
                    background: '#fff', fontSize: 13, cursor: 'pointer',
                  }}
                >
                  Review
                </button>
              )}
            </div>
          ))
        )}
      </div>

      {/* Review History */}
      <div style={{
        background: '#fff', borderRadius: 8, padding: 24,
        boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
      }}>
        <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>
          Review History ({reviewed.length})
        </h2>
        {reviewed.length === 0 ? (
          <p style={{ color: '#6b7280' }}>No review history.</p>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 14 }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #e5e7eb' }}>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Action</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Decision</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Reviewer</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Date</th>
              </tr>
            </thead>
            <tbody>
              {reviewed.map(a => (
                <tr key={a.id} style={{ borderBottom: '1px solid #f3f4f6' }}>
                  <td style={{ padding: '10px 12px' }}>{a.action_type}</td>
                  <td style={{ padding: '10px 12px' }}>
                    <span style={{
                      padding: '2px 8px', borderRadius: 4, fontSize: 12,
                      background: a.status === 'approved' ? '#dcfce7' : '#fecaca',
                      color: a.status === 'approved' ? '#166534' : '#991b1b',
                    }}>
                      {a.status}
                    </span>
                  </td>
                  <td style={{ padding: '10px 12px', color: '#6b7280' }}>{a.reviewed_by}</td>
                  <td style={{ padding: '10px 12px', color: '#6b7280' }}>
                    {a.reviewed_at ? new Date(a.reviewed_at).toLocaleString() : '—'}
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

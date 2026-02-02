/**
 * Evidence Explorer — Browse, search, and verify evidence artifacts.
 *
 * Features:
 * - Searchable evidence list with filters (type, provider, date range)
 * - Hash verification display
 * - Control linkage view
 * - Evidence freshness indicators
 */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

interface EvidenceArtifact {
  id: string;
  system: string;
  artifact_type: string;
  provider: string;
  hash_sha256: string;
  file_size_bytes: number | null;
  control_ids: string[];
  collected_at: string;
  retention_policy: string;
  classification: string;
  storage_uri: string;
}

export default function EvidenceExplorer() {
  const [typeFilter, setTypeFilter] = useState('');
  const [providerFilter, setProviderFilter] = useState('');

  const params = new URLSearchParams();
  if (typeFilter) params.set('artifact_type', typeFilter);
  if (providerFilter) params.set('provider', providerFilter);

  const { data, isLoading } = useQuery<{ results: EvidenceArtifact[] }>({
    queryKey: ['evidence', typeFilter, providerFilter],
    queryFn: () => fetch(`${API_URL}/evidence/?${params}`).then(r => r.json()),
  });

  const artifacts = data?.results || [];

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24, color: '#1a1f36' }}>
        Evidence Explorer
      </h1>

      {/* Filters */}
      <div style={{
        display: 'flex', gap: 12, marginBottom: 20,
        background: '#fff', padding: 16, borderRadius: 8,
        boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
      }}>
        <select
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value)}
          style={{ padding: '6px 12px', borderRadius: 4, border: '1px solid #d1d5db', fontSize: 14 }}
        >
          <option value="">All Types</option>
          <option value="config_snapshot">Config Snapshot</option>
          <option value="log_export">Log Export</option>
          <option value="scan_report">Scan Report</option>
          <option value="ckl">CKL</option>
          <option value="policy_doc">Policy Document</option>
        </select>

        <select
          value={providerFilter}
          onChange={e => setProviderFilter(e.target.value)}
          style={{ padding: '6px 12px', borderRadius: 4, border: '1px solid #d1d5db', fontSize: 14 }}
        >
          <option value="">All Providers</option>
          <option value="aws">AWS</option>
          <option value="aws_gov">AWS GovCloud</option>
          <option value="azure">Azure</option>
          <option value="azure_gov">Azure Gov</option>
          <option value="gcp">GCP</option>
          <option value="gcp_gov">GCP Gov</option>
        </select>
      </div>

      {/* Evidence Table */}
      <div style={{
        background: '#fff', borderRadius: 8, padding: 24,
        boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
      }}>
        {isLoading ? (
          <p style={{ color: '#6b7280' }}>Loading evidence...</p>
        ) : artifacts.length === 0 ? (
          <p style={{ color: '#6b7280' }}>No evidence artifacts found.</p>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 14 }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #e5e7eb' }}>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Type</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Provider</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>SHA-256</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Size</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Controls</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Collected</th>
                <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280' }}>Retention</th>
              </tr>
            </thead>
            <tbody>
              {artifacts.map((a) => (
                <tr key={a.id} style={{ borderBottom: '1px solid #f3f4f6' }}>
                  <td style={{ padding: '10px 12px' }}>
                    <span style={{
                      padding: '2px 8px', borderRadius: 4, fontSize: 12,
                      background: '#eff6ff', color: '#1e40af',
                    }}>
                      {a.artifact_type}
                    </span>
                  </td>
                  <td style={{ padding: '10px 12px', color: '#6b7280' }}>{a.provider || '—'}</td>
                  <td style={{ padding: '10px 12px', fontFamily: 'monospace', fontSize: 11, color: '#6b7280' }}>
                    {a.hash_sha256?.slice(0, 16)}...
                  </td>
                  <td style={{ padding: '10px 12px', color: '#6b7280' }}>
                    {a.file_size_bytes ? `${(a.file_size_bytes / 1024).toFixed(1)} KB` : '—'}
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    {a.control_ids?.slice(0, 3).map(id => (
                      <span key={id} style={{
                        display: 'inline-block', padding: '1px 6px', borderRadius: 3,
                        background: '#f3f4f6', fontSize: 11, marginRight: 4,
                      }}>
                        {id}
                      </span>
                    ))}
                    {a.control_ids?.length > 3 && (
                      <span style={{ fontSize: 11, color: '#6b7280' }}>+{a.control_ids.length - 3}</span>
                    )}
                  </td>
                  <td style={{ padding: '10px 12px', color: '#6b7280' }}>
                    {new Date(a.collected_at).toLocaleDateString()}
                  </td>
                  <td style={{ padding: '10px 12px', color: '#6b7280', fontSize: 12 }}>
                    {a.retention_policy}
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

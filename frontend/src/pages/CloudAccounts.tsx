import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

interface CloudAccount {
  id: string;
  system: string;
  provider: string;
  account_id: string;
  alias: string;
  regions: string[];
  tags: Record<string, string>;
  is_active: boolean;
}

interface System {
  id: string;
  name: string;
  baseline: string;
  owner: string;
  environment: string;
  cloud_accounts: CloudAccount[];
}

const PROVIDERS = [
  { value: 'aws', label: 'AWS' },
  { value: 'aws_gov', label: 'AWS GovCloud' },
  { value: 'azure', label: 'Azure' },
  { value: 'azure_gov', label: 'Azure Government' },
  { value: 'gcp', label: 'GCP' },
  { value: 'gcp_gov', label: 'GCP Government' },
];

const BASELINES = [
  { value: 'fedramp_low', label: 'FedRAMP Low' },
  { value: 'fedramp_mod', label: 'FedRAMP Moderate' },
  { value: 'fedramp_high', label: 'FedRAMP High' },
  { value: 'custom', label: 'Custom' },
];

const PROVIDER_COLORS: Record<string, string> = {
  aws: '#ff9900',
  aws_gov: '#d45b07',
  azure: '#0078d4',
  azure_gov: '#004e8c',
  gcp: '#4285f4',
  gcp_gov: '#1a5276',
};

const card = {
  background: '#fff',
  borderRadius: 8,
  border: '1px solid #e1e4e8',
  padding: 24,
  marginBottom: 20,
};

const input = {
  width: '100%',
  padding: '8px 12px',
  borderRadius: 6,
  border: '1px solid #d0d5dd',
  fontSize: 14,
  boxSizing: 'border-box' as const,
};

const label = {
  display: 'block',
  fontSize: 13,
  fontWeight: 600,
  color: '#344054',
  marginBottom: 4,
};

const btnPrimary = {
  padding: '10px 20px',
  background: '#635bff',
  color: '#fff',
  border: 'none',
  borderRadius: 6,
  fontSize: 14,
  fontWeight: 600,
  cursor: 'pointer',
};

const btnDanger = {
  padding: '6px 12px',
  background: '#ef4444',
  color: '#fff',
  border: 'none',
  borderRadius: 4,
  fontSize: 12,
  cursor: 'pointer',
};

export default function CloudAccounts() {
  const qc = useQueryClient();
  const [showSystemForm, setShowSystemForm] = useState(false);
  const [showAccountForm, setShowAccountForm] = useState(false);
  const [selectedSystem, setSelectedSystem] = useState<string>('');

  // System form state
  const [sysName, setSysName] = useState('');
  const [sysDesc, setSysDesc] = useState('');
  const [sysBaseline, setSysBaseline] = useState('fedramp_mod');
  const [sysOwner, setSysOwner] = useState('');
  const [sysEnv, setSysEnv] = useState('production');

  // Cloud account form state
  const [acctProvider, setAcctProvider] = useState('aws');
  const [acctId, setAcctId] = useState('');
  const [acctAlias, setAcctAlias] = useState('');
  const [acctRegions, setAcctRegions] = useState('');

  const { data: systems = [], isLoading } = useQuery<System[]>({
    queryKey: ['systems'],
    queryFn: async () => {
      const res = await fetch(`${API}/systems/`);
      const json = await res.json();
      return json.results || json;
    },
  });

  const createSystem = useMutation({
    mutationFn: async (data: Record<string, unknown>) => {
      const res = await fetch(`${API}/systems/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['systems'] });
      setShowSystemForm(false);
      setSysName(''); setSysDesc(''); setSysOwner('');
    },
  });

  const createAccount = useMutation({
    mutationFn: async (data: Record<string, unknown>) => {
      const res = await fetch(`${API}/cloud-accounts/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['systems'] });
      setShowAccountForm(false);
      setAcctId(''); setAcctAlias(''); setAcctRegions('');
    },
  });

  const deleteAccount = useMutation({
    mutationFn: async (id: string) => {
      const res = await fetch(`${API}/cloud-accounts/${id}/`, { method: 'DELETE' });
      if (!res.ok && res.status !== 204) throw new Error('Delete failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['systems'] }),
  });

  const handleCreateSystem = (e: React.FormEvent) => {
    e.preventDefault();
    createSystem.mutate({
      name: sysName,
      description: sysDesc,
      baseline: sysBaseline,
      owner: sysOwner,
      environment: sysEnv,
      frameworks: sysBaseline.startsWith('fedramp') ? ['fedramp', 'nist_800_53_r5'] : ['nist_800_53_r5'],
      boundary_definition: {},
    });
  };

  const handleCreateAccount = (e: React.FormEvent) => {
    e.preventDefault();
    createAccount.mutate({
      system: selectedSystem,
      provider: acctProvider,
      account_id: acctId,
      alias: acctAlias,
      regions: acctRegions.split(',').map(r => r.trim()).filter(Boolean),
      tags: {},
    });
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, color: '#1a1f36' }}>Cloud Accounts</h1>
          <p style={{ margin: '4px 0 0', fontSize: 14, color: '#6b7280' }}>
            Manage systems and cloud provider connections
          </p>
        </div>
        <button style={btnPrimary} onClick={() => setShowSystemForm(true)}>
          + New System
        </button>
      </div>

      {/* Create System Form */}
      {showSystemForm && (
        <div style={card}>
          <h3 style={{ margin: '0 0 16px', fontSize: 16 }}>Create New System</h3>
          <form onSubmit={handleCreateSystem}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
              <div>
                <span style={label}>System Name *</span>
                <input style={input} value={sysName} onChange={e => setSysName(e.target.value)} placeholder="e.g., My FedRAMP System" required />
              </div>
              <div>
                <span style={label}>Owner *</span>
                <input style={input} value={sysOwner} onChange={e => setSysOwner(e.target.value)} placeholder="e.g., security-team@example.com" required />
              </div>
              <div>
                <span style={label}>Baseline</span>
                <select style={input} value={sysBaseline} onChange={e => setSysBaseline(e.target.value)}>
                  {BASELINES.map(b => <option key={b.value} value={b.value}>{b.label}</option>)}
                </select>
              </div>
              <div>
                <span style={label}>Environment</span>
                <select style={input} value={sysEnv} onChange={e => setSysEnv(e.target.value)}>
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="development">Development</option>
                </select>
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <span style={label}>Description</span>
                <input style={input} value={sysDesc} onChange={e => setSysDesc(e.target.value)} placeholder="Brief description of the system boundary" />
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button type="submit" style={btnPrimary} disabled={createSystem.isPending}>
                {createSystem.isPending ? 'Creating...' : 'Create System'}
              </button>
              <button type="button" style={{ ...btnPrimary, background: '#6b7280' }} onClick={() => setShowSystemForm(false)}>
                Cancel
              </button>
            </div>
            {createSystem.isError && (
              <p style={{ color: '#ef4444', fontSize: 13, marginTop: 8 }}>
                Error: {(createSystem.error as Error).message}
              </p>
            )}
          </form>
        </div>
      )}

      {/* Systems List */}
      {isLoading ? (
        <p style={{ color: '#6b7280' }}>Loading systems...</p>
      ) : systems.length === 0 ? (
        <div style={{ ...card, textAlign: 'center', padding: 48 }}>
          <p style={{ fontSize: 16, color: '#6b7280', margin: 0 }}>No systems configured yet.</p>
          <p style={{ fontSize: 14, color: '#9ca3af', margin: '8px 0 0' }}>
            Click "+ New System" to create your first ATO boundary.
          </p>
        </div>
      ) : (
        systems.map(sys => (
          <div key={sys.id} style={card}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: 16 }}>{sys.name}</h3>
                <p style={{ margin: '4px 0 0', fontSize: 13, color: '#6b7280' }}>
                  {sys.baseline.replace(/_/g, ' ').toUpperCase()} &middot; {sys.environment} &middot; {sys.owner}
                </p>
              </div>
              <button
                style={btnPrimary}
                onClick={() => { setSelectedSystem(sys.id); setShowAccountForm(true); }}
              >
                + Add Cloud Account
              </button>
            </div>

            {/* Add Account Form (inline) */}
            {showAccountForm && selectedSystem === sys.id && (
              <div style={{ background: '#f9fafb', border: '1px solid #e5e7eb', borderRadius: 6, padding: 16, marginBottom: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 14 }}>Connect Cloud Account</h4>
                <form onSubmit={handleCreateAccount}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 12 }}>
                    <div>
                      <span style={label}>Provider *</span>
                      <select style={input} value={acctProvider} onChange={e => setAcctProvider(e.target.value)}>
                        {PROVIDERS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
                      </select>
                    </div>
                    <div>
                      <span style={label}>Account / Subscription / Project ID *</span>
                      <input style={input} value={acctId} onChange={e => setAcctId(e.target.value)} placeholder="e.g., 123456789012" required />
                    </div>
                    <div>
                      <span style={label}>Alias</span>
                      <input style={input} value={acctAlias} onChange={e => setAcctAlias(e.target.value)} placeholder="e.g., Production AWS" />
                    </div>
                    <div style={{ gridColumn: '1 / -1' }}>
                      <span style={label}>Regions (comma-separated)</span>
                      <input style={input} value={acctRegions} onChange={e => setAcctRegions(e.target.value)} placeholder="e.g., us-east-1, us-west-2" />
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button type="submit" style={btnPrimary} disabled={createAccount.isPending}>
                      {createAccount.isPending ? 'Connecting...' : 'Connect Account'}
                    </button>
                    <button type="button" style={{ ...btnPrimary, background: '#6b7280' }} onClick={() => setShowAccountForm(false)}>
                      Cancel
                    </button>
                  </div>
                  {createAccount.isError && (
                    <p style={{ color: '#ef4444', fontSize: 13, marginTop: 8 }}>
                      Error: {(createAccount.error as Error).message}
                    </p>
                  )}
                </form>
              </div>
            )}

            {/* Connected Accounts Table */}
            {sys.cloud_accounts && sys.cloud_accounts.length > 0 ? (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 14 }}>
                <thead>
                  <tr style={{ borderBottom: '2px solid #e5e7eb' }}>
                    <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280', fontWeight: 600, fontSize: 12, textTransform: 'uppercase' }}>Provider</th>
                    <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280', fontWeight: 600, fontSize: 12, textTransform: 'uppercase' }}>Account ID</th>
                    <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280', fontWeight: 600, fontSize: 12, textTransform: 'uppercase' }}>Alias</th>
                    <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280', fontWeight: 600, fontSize: 12, textTransform: 'uppercase' }}>Regions</th>
                    <th style={{ textAlign: 'left', padding: '8px 12px', color: '#6b7280', fontWeight: 600, fontSize: 12, textTransform: 'uppercase' }}>Status</th>
                    <th style={{ textAlign: 'right', padding: '8px 12px', color: '#6b7280', fontWeight: 600, fontSize: 12, textTransform: 'uppercase' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {sys.cloud_accounts.map(acct => (
                    <tr key={acct.id} style={{ borderBottom: '1px solid #f3f4f6' }}>
                      <td style={{ padding: '10px 12px' }}>
                        <span style={{
                          display: 'inline-block',
                          padding: '2px 10px',
                          borderRadius: 12,
                          fontSize: 12,
                          fontWeight: 600,
                          color: '#fff',
                          background: PROVIDER_COLORS[acct.provider] || '#6b7280',
                        }}>
                          {acct.provider.replace('_', ' ').toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: '10px 12px', fontFamily: 'monospace', fontSize: 13 }}>{acct.account_id}</td>
                      <td style={{ padding: '10px 12px' }}>{acct.alias || '—'}</td>
                      <td style={{ padding: '10px 12px', fontSize: 13 }}>{acct.regions?.join(', ') || '—'}</td>
                      <td style={{ padding: '10px 12px' }}>
                        <span style={{
                          display: 'inline-block',
                          padding: '2px 8px',
                          borderRadius: 12,
                          fontSize: 12,
                          fontWeight: 500,
                          color: acct.is_active ? '#059669' : '#dc2626',
                          background: acct.is_active ? '#ecfdf5' : '#fef2f2',
                        }}>
                          {acct.is_active ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td style={{ padding: '10px 12px', textAlign: 'right' }}>
                        <button
                          style={btnDanger}
                          onClick={() => { if (confirm('Remove this cloud account?')) deleteAccount.mutate(acct.id); }}
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p style={{ color: '#9ca3af', fontSize: 13, margin: 0 }}>
                No cloud accounts connected. Click "+ Add Cloud Account" to get started.
              </p>
            )}
          </div>
        ))
      )}
    </div>
  );
}

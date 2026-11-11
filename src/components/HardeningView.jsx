import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { ClipboardCheck, CircleAlert } from 'lucide-react';

const PAGE_SIZE = 25;
const STATUS_TONE = {
  Compliant: 'green',
  NonCompliant: 'red',
  MissingKey: 'amber',
  MissingValue: 'amber',
  AccessDenied: 'amber',
  NotApplicable: '',
  ManagedExternally: 'amber',
  UnknownEffectiveState: 'amber',
};

export default function HardeningView({ native, t, formatNumber }) {
  const [report, setReport] = useState(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const [page, setPage] = useState(0);

  async function runAudit() {
    if (!native || running) return;
    setRunning(true);
    setError('');
    setReport(null);
    setPage(0);
    try {
      setReport(await invoke('audit_hardening'));
    } catch (cause) {
      setError(String(cause));
    } finally {
      setRunning(false);
    }
  }

  const results = report?.results ?? [];
  const first = page * PAGE_SIZE;
  const visible = results.slice(first, first + PAGE_SIZE);
  return <>
    <div className="warning"><ClipboardCheck size={18}/><span>{t('hardeningTechnical')}</span></div>
    <section className="panel">
      <div className="panel-heading"><h2><ClipboardCheck size={18}/>{t('hardening')}</h2></div>
      <div className="panel-body">
        <p className="intro">{t('hardeningIntro')}</p>
        <button className="primary" disabled={!native || running} onClick={runAudit} aria-busy={running}>
          <ClipboardCheck/>{t(running ? 'hardeningRunning' : 'hardeningRun')}
        </button>
        {!native && <p className="muted">{t('hardeningPreview')}</p>}
        {error && <div className="warning" role="alert"><CircleAlert size={18}/>{error}</div>}
      </div>
    </section>
    {report && <section className="panel">
      <div className="panel-heading"><h2>{t('hardeningSummary')}</h2></div>
      <div className="panel-body metrics">
        <div className="metric"><span>{t('hardeningCompliant')}</span><strong>{formatNumber(report.compliant)}</strong></div>
        <div className="metric"><span>{t('hardeningNonCompliant')}</span><strong>{formatNumber(report.non_compliant)}</strong></div>
        <div className="metric"><span>{t('hardeningInconclusive')}</span><strong>{formatNumber(report.inconclusive)}</strong></div>
      </div>
    </section>}
    <section className="panel">
      <div className="panel-heading"><h2>{t('hardeningResults')}</h2>{report && <span className="badge">{formatNumber(report.total)}</span>}</div>
      <div className="panel-body">
        {!report ? <div className="empty"><ClipboardCheck size={28}/><p>{t('hardeningNoResults')}</p></div>
          : <>
            <div className="table-wrap"><table className="hardening-table"><thead><tr>
              <th>{t('hardening')}</th><th>{t('hardeningObserved')}</th><th>{t('hardeningExpected')}</th><th>{t('hardeningReason')}</th>
            </tr></thead><tbody>{visible.map(item => <tr key={item.id}>
              <td><strong>{item.title}</strong><span className="secondary">{item.category}</span>
                <p className="muted">{item.description}</p></td>
              <td><span className={'badge ' + (STATUS_TONE[item.status] ?? 'amber')}>{t(item.status)}</span>
                <code>{item.observed ?? '—'}</code></td>
              <td><code>{item.expected}</code></td>
              <td><p>{item.reason}</p><small>{t('hardeningSource')}</small><code>{item.source_url}</code></td>
            </tr>)}</tbody></table></div>
            {results.length > PAGE_SIZE && <div className="hardening-pages">
              <button aria-label={t('hardeningPrevious')} disabled={page === 0} onClick={() => setPage(page - 1)}>←</button>
              <span>{first + 1}–{Math.min(first + PAGE_SIZE, results.length)} / {results.length}</span>
              <button aria-label={t('hardeningNext')} disabled={first + PAGE_SIZE >= results.length} onClick={() => setPage(page + 1)}>→</button>
            </div>}
          </>}
      </div>
    </section>
  </>;
}

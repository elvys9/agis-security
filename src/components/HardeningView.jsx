import React, { useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { ClipboardCheck, CircleAlert, Sparkles } from 'lucide-react';

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

export default function HardeningView({ native, language, t, formatNumber }) {
  const [report, setReport] = useState(null);
  const [running, setRunning] = useState(false);
  const [explaining, setExplaining] = useState(false);
  const [explanation, setExplanation] = useState(null);
  const [error, setError] = useState('');
  const [page, setPage] = useState(0);
  const requestVersion = useRef(0);

  useEffect(() => {
    requestVersion.current += 1;
    setExplanation(null);
  }, [language]);

  async function runAudit() {
    if (!native || running) return;
    const version = ++requestVersion.current;
    setRunning(true);
    setError('');
    setReport(null);
    setExplanation(null);
    setPage(0);
    try {
      const result = await invoke('audit_hardening');
      if (version === requestVersion.current) setReport(result);
    } catch (cause) {
      if (version === requestVersion.current) setError(String(cause));
    } finally {
      setRunning(false);
    }
  }

  async function explainResults() {
    if (!native || !report || explaining || running) return;
    const version = ++requestVersion.current;
    setExplaining(true);
    setError('');
    setExplanation(null);
    try {
      const result = await invoke('explain_hardening', { language });
      if (version === requestVersion.current) {
        setReport(result.report);
        setExplanation(result);
        setPage(0);
      }
    } catch (cause) {
      if (version === requestVersion.current) setError(String(cause));
    } finally {
      setExplaining(false);
    }
  }

  const results = report?.results ?? [];
  const byId = new Map(results.map(item => [item.id, item]));
  const first = page * PAGE_SIZE;
  const visible = results.slice(first, first + PAGE_SIZE);
  return <>
    <div className="warning"><ClipboardCheck size={18}/><span>{t('hardeningTechnical')}</span></div>
    <section className="panel">
      <div className="panel-heading"><h2><ClipboardCheck size={18}/>{t('hardening')}</h2></div>
      <div className="panel-body">
        <p className="intro">{t('hardeningIntro')}</p>
        <div className="actions">
          <button className="primary" disabled={!native || running || explaining} onClick={runAudit} aria-busy={running}>
            <ClipboardCheck/>{t(running ? 'hardeningRunning' : 'hardeningRun')}
          </button>
          {report && <button disabled={!native || running || explaining} onClick={explainResults} aria-busy={explaining}>
            <Sparkles/>{t(explaining ? 'hardeningExplaining' : 'hardeningExplain')}
          </button>}
        </div>
        {report && <p className="muted">{t('hardeningModelInfo')}</p>}
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
    {explanation && <section className="panel" aria-live="polite">
      <div className="panel-heading"><h2>{t('hardeningPlainTitle')}</h2></div>
      <div className="panel-body hardening-report">
        <p>{t('hardeningMatchingCount', { count: formatNumber(explanation.plain.matching_count) })}</p>
        <div className="hardening-report-groups">
          <div><h3>{t('hardeningDifferentList')}</h3>
            {explanation.plain.differing_ids.length ? <ul>{explanation.plain.differing_ids.map(id =>
              <li key={id}>{byId.get(id)?.title ?? id}</li>)}</ul> : <p className="muted">{t('hardeningNoDifferences')}</p>}
          </div>
          <div><h3>{t('hardeningUncertainList')}</h3>
            {explanation.plain.uncertain_ids.length ? <ul>{explanation.plain.uncertain_ids.map(id =>
              <li key={id}>{byId.get(id)?.title ?? id} · {t(byId.get(id)?.status ?? 'UnknownEffectiveState')}</li>)}</ul>
              : <p className="muted">{t('hardeningNoUncertainties')}</p>}
          </div>
        </div>
        <p className="muted" role="status">{t(explanation.model_state)}</p>
        {explanation.ai && <div className="hardening-ai">
          <h3><Sparkles size={17}/>{t('hardeningAiTitle')}</h3>
          <p>{explanation.ai.summary}</p>
          {explanation.ai.advice.length > 0 && <ul>{explanation.ai.advice.map(advice =>
            <li key={advice.rule_id}><strong>{byId.get(advice.rule_id)?.title ?? advice.rule_id}:</strong> {advice.text}</li>)}</ul>}
          <p className="muted">{t('hardeningAiCaution')}</p>
        </div>}
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

import React, { useEffect, useRef, useState } from 'react';
import { invoke, isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow';
import { open, confirm } from '@tauri-apps/plugin-dialog';
import { enable, disable, isEnabled } from '@tauri-apps/plugin-autostart';
import {
  ShieldCheck, ShieldAlert, LayoutDashboard, ScanLine, Archive, Terminal,
  Activity, Play, Pause, Square, FolderOpen, FileSearch, Database,
  RotateCcw, Trash2, CircleAlert, X, Download, Languages,
} from 'lucide-react';
import { languages, initialLanguage, translate, translateEngineText, formatNumber } from './i18n.js';

const native = isTauri();
const NAV = [
  ['dashboard', 'dashboard', LayoutDashboard],
  ['scanner', 'scanner', ScanLine],
  ['quarantine', 'quarantine', Archive],
  ['inspector', 'settings', Terminal],
];
const pageHelp = {
  dashboard: 'dashboardHelp', scanner: 'scannerHelp',
  quarantine: 'quarantineHelp', inspector: 'settingsHelp',
};

function Panel({ title, icon: Icon, children, action }) {
  return <section className="panel">
    <div className="panel-heading"><h2>{Icon && <Icon size={18}/>} {title}</h2>{action}</div>
    <div className="panel-body">{children}</div>
  </section>;
}
function Badge({ children, tone = '' }) { return <span className={'badge ' + tone}>{children}</span>; }
function Metric({ label, value, suffix }) {
  return <div className="metric"><span>{label}</span><strong>{value ?? '—'}<small>{suffix}</small></strong></div>;
}

export default function App() {
  const [language, setLanguage] = useState(() => initialLanguage());
  const languageRef = useRef(language);
  languageRef.current = language;
  const t = (key, values) => translate(languageRef.current, key, values);
  const n = value => formatNumber(language, value);
  const [view, setView] = useState('dashboard');
  const [status, setStatus] = useState(null);
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [vault, setVault] = useState([]);
  const [logs, setLogs] = useState([]);
  const [notice, setNotice] = useState(null);
  const [pending, setPending] = useState(false);
  const [autostart, setAutostart] = useState(null);
  const [dragging, setDragging] = useState(false);
  const gate = useRef(false);
  const currentScan = useRef(null);
  currentScan.current = scan;
  const busy = scan?.status === 'running' || scan?.status === 'paused';
  const ready = native && !!status && !pending;

  useEffect(() => {
    document.documentElement.lang = language;
    try { localStorage.setItem('aegis.language', language); } catch { /* Browser storage may be disabled. */ }
    if (native) invoke('set_ui_language', { language }).catch(reportError);
  }, [language]);

  function log(key, values = {}) {
    setLogs(old => [...old.slice(-199), { time: new Date().toLocaleTimeString(), key, values }]);
  }
  function addFinding(finding) {
    setFindings(old => [finding, ...old.filter(item => item.id !== finding.id)]);
  }
  function reportError(error) {
    const message = String(error);
    setNotice({ raw: message });
    log('raw', { message });
  }
  async function run(action) {
    if (!native || gate.current) return;
    gate.current = true;
    setPending(true);
    try { await action(); } catch (error) { reportError(error); }
    finally { gate.current = false; setPending(false); }
  }
  async function refresh() {
    const responses = await Promise.allSettled([
      invoke('get_status'), invoke('get_scan_snapshot'), invoke('get_findings'), invoke('list_quarantine'),
    ]);
    const setters = [setStatus, setScan, setFindings, setVault];
    responses.forEach((result, index) => {
      if (result.status === 'fulfilled') setters[index](result.value);
    });
    const errors = responses.filter(result => result.status === 'rejected').map(result => String(result.reason));
    if (errors.length) {
      const details = errors.join('; ');
      setNotice({ key: 'partialData', values: { details } });
      log('partialUpdate', { details });
    }
  }
  async function start(mode, paths = []) {
    if (['running', 'paused'].includes(currentScan.current?.status)) {
      setNotice({ key: 'scanAlreadyRunning' });
      return;
    }
    await invoke('start_scan', { mode, paths });
    setView('scanner');
    setScan(await invoke('get_scan_snapshot'));
    log('scanStarted', { mode: t(mode === 'quick' ? 'quickScan' : mode === 'full' ? 'fullScan' : 'scanner') });
  }

  useEffect(() => {
    if (!native) return;
    let disposed = false;
    const cleanup = [];
    async function subscribe(promise) {
      const unlisten = await promise;
      if (disposed) unlisten();
      else cleanup.push(unlisten);
    }
    async function init() {
      try {
        await Promise.all([
          subscribe(listen('scan-progress', ({ payload }) => { if (!disposed) setScan(payload); })),
          subscribe(listen('scan-finding', ({ payload }) => { if (!disposed) addFinding(payload); })),
          subscribe(listen('watcher-alert', ({ payload }) => {
            if (!disposed) { addFinding(payload); log('monitorLog', { path: payload.path }); }
          })),
          subscribe(listen('engine-status', ({ payload }) => { if (!disposed) setStatus(payload); })),
          subscribe(listen('scan-error', ({ payload }) => { if (!disposed) reportError(payload); })),
          subscribe(getCurrentWebviewWindow().onDragDropEvent(({ payload }) => {
            if (disposed) return;
            setDragging(payload.type === 'over' || payload.type === 'enter');
            if (payload.type === 'drop') run(() => start('custom', payload.paths));
          })),
        ]);
        if (!disposed) { await refresh(); log('nativeLog'); }
        try {
          const enabled = await isEnabled();
          if (!disposed) setAutostart(enabled);
        } catch (error) {
          if (!disposed) log('autostartError', { details: String(error) });
        }
      } catch (error) {
        if (!disposed) {
          reportError(error);
          log('connectionError', { details: String(error) });
        }
      }
    }
    init();
    return () => { disposed = true; cleanup.forEach(fn => fn()); };
  }, []);

  async function pick(directory) {
    const result = await open({
      directory, multiple: true, title: t(directory ? 'pickFolders' : 'pickFiles'),
    });
    if (result) await start('custom', Array.isArray(result) ? result : [result]);
  }
  async function isolate(item) {
    await invoke('quarantine_file', { findingId: item.id });
    await refresh();
    setNotice({ key: 'isolated' });
  }
  async function vaultAction(item, restore) {
    const accepted = await confirm(
      t(restore ? 'restoreConfirm' : 'deleteConfirm', { path: item.original_path }),
      { title: t(restore ? 'restoreTitle' : 'deleteTitle'), kind: 'warning' },
    );
    if (!accepted) return;
    const result = await invoke(restore ? 'restore_quarantine' : 'delete_quarantine', { id: item.id });
    await refresh();
    setNotice(restore ? { key: 'restored', values: { path: result } } : { key: 'deleted' });
  }
  function scanButtons() {
    return <div className="actions">
      <button className="primary" disabled={!ready || busy} onClick={() => run(() => start('quick'))}><Play/>{t('quickScan')}</button>
      <button disabled={!ready || busy} onClick={() => run(() => start('full'))}><ScanLine/>{t('fullScan')}</button>
      <button disabled={!ready || busy} onClick={() => run(() => pick(false))}><FileSearch/>{t('selectFiles')}</button>
      <button disabled={!ready || busy} onClick={() => run(() => pick(true))}><FolderOpen/>{t('selectFolders')}</button>
    </div>;
  }
  function results() {
    return <Panel title={t('evidence')} icon={ShieldAlert} action={<Badge>{t('findingCount', { count: n(findings.length) })}</Badge>}>
      {!findings.length
        ? <div className="empty"><ShieldCheck size={28}/><h3>{t(status ? 'noFindings' : 'waitingEngine')}</h3>
            <p>{t(status ? 'findingsHint' : 'launchDesktop')}</p></div>
        : <div className="table-wrap"><table><thead><tr>
            <th>{t('filePath')}</th><th>{t('analysis')}</th><th>{t('severity')}</th><th>{t('action')}</th>
          </tr></thead><tbody>{findings.map(item => <tr key={item.id}>
            <td><strong>{item.name}</strong><code>{item.path}</code>
              <details><summary>{t('hashes')}</summary><code>SHA-256: {item.sha256}</code><code>MD5: {item.md5}</code></details>
            </td>
            <td>{t(item.verdict === 'malicious' ? 'malicious' : 'suspicious')}
              <span className="secondary">{t('entropy')}: {Number(item.entropy).toFixed(2)}</span>
              {item.anomalies.map((anomaly, i) => <span className="secondary" key={i}>{translateEngineText(language, anomaly)}</span>)}
              {item.coverage?.map((warning, i) => <span className="secondary amber-text" key={'coverage-' + i}>{translateEngineText(language, warning)}</span>)}
            </td>
            <td><Badge tone={item.severity === 'Alta' ? 'red' : 'amber'}>{t(item.severity === 'Alta' ? 'high' : 'medium')}</Badge></td>
            <td><button disabled={!ready} onClick={() => run(() => isolate(item))}><Archive/>{t('isolate')}</button></td>
          </tr>)}</tbody></table></div>}
    </Panel>;
  }
  const noticeText = notice?.key
    ? t(notice.key, notice.values)
    : translateEngineText(language, notice?.raw);
  return <div className="app">
    <aside>
      <div className="brand"><ShieldCheck size={32}/><div><strong>Aegis Security</strong><span>Endpoint security</span></div></div>
      <nav aria-label={t('dashboard')}>
        {NAV.map(([id, title, Icon]) => <button key={id} aria-current={view === id ? 'page' : undefined} onClick={() => setView(id)}>
          <Icon size={18}/>{t(title)}
        </button>)}
      </nav>
      <div className="sidebar-foot">
        <Badge tone={status ? 'green' : 'amber'}>{t(status ? 'engineLocal' : 'engineUnavailable')}</Badge>
        <p>{t('sidebarInfo')}</p><span>{status ? 'v' + status.version : 'Desktop Windows · Tauri'}</span>
      </div>
    </aside>
    <div className="workspace">
      <header>
        <div><span className={status ? 'green-text' : 'amber-text'}>
          {t(status ? 'connected' : native ? 'connecting' : 'preview')}
        </span><p>{status
          ? t('workerStatus', { count: status.workers, state: t(status.watcher_enabled ? 'on' : 'off') })
          : t('desktopOnly')}</p></div>
        <div className="header-actions">
          <label className="language-control">
            <Languages size={16} aria-hidden="true"/>
            <span>{t('language')}</span>
            <select aria-label={t('language')} value={language} onChange={event => setLanguage(event.target.value)}>
              {languages.map(item => <option key={item.code} value={item.code}>{item.label}</option>)}
            </select>
          </label>
          <button disabled={!native || pending} onClick={() => run(refresh)}><RotateCcw/>{t('refresh')}</button>
        </div>
      </header>
      <main>
        <div className="page-heading"><div><h1>{t(NAV.find(item => item[0] === view)[1])}</h1><p>{t(pageHelp[view])}</p></div>
          <Badge tone={busy ? 'amber' : ''}>{scan ? t(scan.status) : t('disconnected')}</Badge></div>
        {status?.warnings?.map((warning, i) => <div className="warning" key={i}><CircleAlert size={18}/>{translateEngineText(language, warning)}</div>)}
        {view === 'dashboard' && <>
          <div className="dashboard-grid">
            <Panel title={t('systemStatus')} icon={ShieldCheck}>
              <div className="system-status"><ShieldCheck size={46}/><div><h3>{t(status ? 'engineAvailable' : 'engineUnavailable')}</h3>
                <p>{t(status?.watcher_enabled ? 'watcherEnabled' : 'watcherDisabled')}</p></div></div>
              <div className="setting"><div><strong>{t('fileMonitoring')}</strong><p>{t('watcherDetails')}</p></div>
                <button role="switch" aria-checked={!!status?.watcher_enabled} disabled={!ready}
                  onClick={() => run(async () => { await invoke('set_watcher', { enabled: !status.watcher_enabled }); await refresh(); })}>
                  {t(status?.watcher_enabled ? 'enabled' : 'disabled')}
                </button></div>
              <p className="muted">{t('monitoringLimit')}</p>
            </Panel>
            <Panel title={t('onDemand')} icon={ScanLine}>
              <p className="intro">{t('inspectLocal')}</p>{scanButtons()}
              <div className="metrics compact"><Metric label={t('analyzedFiles')} value={scan ? n(scan.files) : null}/>
                <Metric label={t('lastStatus')} value={scan ? t(scan.status) : null}/></div>
            </Panel>
            <Panel title={t('detectionsVault')} icon={Archive}>
              <div className="metrics"><Metric label={t('toReview')} value={status ? n(findings.length) : null}/>
                <Metric label={t('vaultItems')} value={status ? n(vault.length) : null}/></div>
              <button className="wide" onClick={() => setView('quarantine')}><Archive/>{t('manageVault')}</button>
            </Panel>
            <Panel title={t('signatures')} icon={Database}>
              <div className="metrics"><Metric label={t('definitionsVersion')} value={status ? String(status.definitions_version) : null}/></div>
              <p className="muted">{t(status?.update_configured ? 'updateConfigured' : 'updateMissing')}</p>
              <button disabled={!ready || !status?.update_configured} onClick={() => run(async () => {
                const response = await invoke('check_updates');
                setNotice({ raw: response.message }); await refresh();
              })}><Download/>{t('checkUpdates')}</button>
            </Panel>
          </div>{results()}
        </>}
        {view === 'scanner' && <>
          {scanButtons()}
          <div className={'drop-zone ' + (dragging ? 'dragging' : '')}><FolderOpen size={22}/>
            <span>{t(native ? 'dropHint' : 'dropDesktop')}</span></div>
          <Panel title={t(scan?.status ?? 'engineUnavailable')} icon={ScanLine} action={<div className="actions">
            <button disabled={!ready || !busy} onClick={() => run(async () => {
              await invoke('pause_scan', { paused: scan.status !== 'paused' });
              setScan(await invoke('get_scan_snapshot'));
            })}>{scan?.status === 'paused' ? <Play/> : <Pause/>}{t(scan?.status === 'paused' ? 'resume' : 'pause')}</button>
            <button disabled={!ready || !busy} onClick={() => run(async () => {
              await invoke('cancel_scan'); setScan(await invoke('get_scan_snapshot'));
            })}><Square/>{t('stop')}</button>
          </div>}>
            <div className="metrics">
              <Metric label={t('analyzedFiles')} value={scan ? n(scan.files) : null}/>
              <Metric label={t('currentRate')} value={scan ? n(scan.rate) : null} suffix=" file/s"/>
              <Metric label={t('detections')} value={scan ? n(scan.found) : null}/>
              <Metric label={t('readErrors')} value={scan ? n(scan.errors) : null}/>
              <Metric label={t('incomplete')} value={scan ? n(scan.incomplete) : null}/>
            </div>
            {busy && <div className={'progress ' + (scan.status === 'paused' ? 'paused' : '')} role="progressbar"
              aria-label={t('progressAria')}><span/></div>}
            <code className="scan-path">{scan?.path || t('noFile')}</code>
            <p className="muted">{t('unknownTotal')}</p>
          </Panel>{results()}
        </>}
        {view === 'quarantine' && <>
          <div className="warning"><Archive size={18}/><span>{t('vaultInfo')}</span></div>
          {!vault.length
            ? <Panel title={t('quarantine')} icon={Archive}><div className="empty"><Archive size={32}/>
                <h3>{t(status ? 'emptyVault' : 'vaultUnavailable')}</h3>
                <p>{t(status ? 'isolateHint' : 'connectVault')}</p></div></Panel>
            : vault.map(item => <Panel key={item.id} title={item.original_path.split(/[\\/]/).pop() || item.id}
                icon={Archive} action={<Badge tone={item.status === 'held' ? 'green' : 'amber'}>
                  {t(item.status === 'held' ? 'held' : item.status === 'damaged' ? 'damaged' : 'originalPresent')}
                </Badge>}>
                <code>{item.original_path}</code>
                <p className="muted">{translateEngineText(language, item.reason)} · {n(item.size)} byte · {item.created_at}</p>
                <details><summary>SHA-256</summary><code>{item.sha256}</code></details>
                {item.status === 'original_retained' && <p className="amber-text">{t('originalRetained')}</p>}
                <div className="actions">
                  <button disabled={!ready || item.status === 'damaged'} onClick={() => run(() => vaultAction(item, true))}>
                    <RotateCcw/>{t('restore')}</button>
                  <button className="danger" disabled={!ready} onClick={() => run(() => vaultAction(item, false))}>
                    <Trash2/>{t('delete')}</button>
                </div>
              </Panel>)}
        </>}
        {view === 'inspector' && <div className="dashboard-grid">
          <Panel title={t('settings')} icon={Activity}>
            <div className="setting"><div><strong>{t('autostart')}</strong><p>{t('autostartDetails')}</p></div>
              <button role="switch" aria-checked={autostart === true} disabled={!ready || autostart === null}
                onClick={() => run(async () => {
                  await (autostart ? disable() : enable()); setAutostart(await isEnabled());
                })}>{t(autostart === null ? 'unavailable' : autostart ? 'enabled' : 'disabled')}</button></div>
            <h3>{t('localVault')}</h3><code>{status?.vault_path || t('unavailable')}</code>
            <p className="muted">{t('currentUserRights')}</p>
          </Panel>
          <Panel title={t('sessionEvents')} icon={Terminal}>
            <div className="event-log" role="log" tabIndex={0}>
              {logs.length
                ? logs.map((entry, i) => <p key={i}><time>{entry.time}</time> {
                    entry.key === 'raw'
                      ? translateEngineText(language, entry.values.message)
                      : t(entry.key, entry.values)
                  }</p>)
                : <p>{t('noEvents')}</p>}
            </div>
          </Panel>
        </div>}
      </main>
    </div>
    {notice && <div className="notice" role="status"><CircleAlert size={20}/><p>{noticeText}</p>
      <button aria-label={t('closeNotice')} onClick={() => setNotice(null)}><X/></button></div>}
  </div>;
}

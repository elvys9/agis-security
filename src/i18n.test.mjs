import assert from 'node:assert/strict';
import test from 'node:test';
import {
  languages, messages, initialLanguage, translate, translateEngineText, formatNumber,
} from './i18n.js';

test('all six locales cover every interface message and interpolation field', () => {
  assert.deepEqual(languages.map(item => item.code), ['en', 'it', 'fr', 'de', 'zh-CN', 'ru']);
  const englishKeys = Object.keys(messages.en).sort();
  for (const { code } of languages) {
    assert.deepEqual(Object.keys(messages[code]).sort(), englishKeys, code);
    for (const key of englishKeys) {
      assert.ok(messages[code][key].trim(), code + ':' + key);
      const placeholders = text => [...text.matchAll(/\{(\w+)\}/g)].map(match => match[1]).sort();
      assert.deepEqual(placeholders(messages[code][key]), placeholders(messages.en[key]), code + ':' + key);
    }
  }
});

test('saved language and unsupported values have predictable defaults', () => {
  assert.equal(initialLanguage({ getItem: () => 'zh-CN' }), 'zh-CN');
  assert.equal(initialLanguage({ getItem: () => 'unknown' }), 'en');
  assert.equal(initialLanguage({ getItem: () => { throw Error('disabled'); } }), 'en');
  assert.equal(translate('de', 'restored', { path: 'C:\\sample.exe' }), 'Datei wiederhergestellt: C:\\sample.exe');
  assert.equal(formatNumber('fr', 1200), new Intl.NumberFormat('fr-FR').format(1200));
});

test('native health and coverage messages preserve counts and technical details', () => {
  assert.match(translateEngineText('ru', 'Watcher: 12 eventi persi o non analizzabili; copertura degradata.'), /12/);
  assert.match(translateEngineText('zh-CN', 'High entropy executable section .text'), /\.text/);
  assert.match(translateEngineText('fr', 'PE incomplete: Invalid PE header offset'), /Invalid PE header offset/);
  assert.equal(translateEngineText('de', 'SHA-256: EICAR'), 'SHA-256: EICAR');
});

test('read-only hardening controls and all eight outcomes are translated', () => {
  const keys = [
    'hardening', 'hardeningHelp', 'hardeningIntro', 'hardeningRun',
    'hardeningRunning', 'hardeningPreview', 'hardeningNoResults',
    'hardeningSummary', 'hardeningCompliant', 'hardeningNonCompliant',
    'hardeningInconclusive', 'hardeningObserved', 'hardeningExpected',
    'hardeningSource', 'hardeningReason', 'hardeningTechnical',
    'hardeningResults', 'hardeningPrevious', 'hardeningNext',
    'Compliant', 'NonCompliant', 'MissingKey', 'MissingValue',
    'AccessDenied', 'NotApplicable', 'ManagedExternally', 'UnknownEffectiveState',
  ];
  for (const { code } of languages) {
    for (const key of keys) {
      assert.ok(messages[code][key]?.trim(), code + ':' + key);
      assert.notEqual(translate(code, key), key, code + ':' + key);
    }
  }
});

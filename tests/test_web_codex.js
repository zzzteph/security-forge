// Behavioral checks for scan controls; no browser or npm packages required.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
let component;
vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../webapp/static/app.js'), 'utf8'), {
  Vue: { createApp: options => { component = options; return { mount() {} }; } },
  URLSearchParams,
});

(async () => {
  const calls = [];
  const state = {
    ...component.data(), ...component.methods,
    api: async (method, url) => calls.push({ method, url }),
    notify() {}, loadRepos: async () => {},
  };
  const repo = { id: 1, name: 'example' };
  state.runScan(repo);
  await state.startScan();
  assert.equal(new URL(calls[0].url, 'http://localhost').searchParams.has('effort'), false);
  repo.last_status = 'done';
  state.runScan(repo);
  state.scanModal.useDefault = false;
  state.scanModal.level = 3;
  await state.startScan();
  assert.equal(new URL(calls[1].url, 'http://localhost').searchParams.get('effort'), 'high');
  assert.equal(state.money(null), 'not reported');
  assert.equal(state.money(0), '$0.00');
  state.settings.defaults.backend = 'litellm';
  state.settings.defaults.model = 'ChatGPT 5.4';
  state.modelChanged();
  assert.equal(state.settings.defaults.backend, 'auto');
  assert.equal(state.canAuth({ available: true, name: 'codex', browser_auth: false }), false);
  assert.match(state.scanTokens({ usage_json: '{"input_tokens":100,"cached_input_tokens":80,"output_tokens":20}' }), /100 input \(80 cached\)/);
  console.log('Scan defaults, explicit effort, CLI login and token display: OK');
})().catch(error => { console.error(error); process.exitCode = 1; });

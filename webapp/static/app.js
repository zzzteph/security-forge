const { createApp } = Vue;

const SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const TRIAGE_LABELS = { unset: 'Untriaged', confirmed: 'Confirmed',
  false_positive: 'False positive', accepted_risk: 'Accepted risk',
  wont_fix: "Won't fix", duplicate: 'Duplicate' };
const TRIAGE_SHORT = { confirmed: '✓ real', false_positive: 'false positive',
  accepted_risk: 'accepted', wont_fix: "won't fix", duplicate: 'duplicate' };

createApp({
  data() {
    return {
      ready: false, me: null, view: 'dashboard',
      login: { username: 'root', password: '', err: '' },
      pw: { show: false, current: '', next: '', msg: '', err: '' },
      counts: {}, findings: [], findingFilter: { status: 'open', min_sev: '', triage: '' },
      commentDraft: '', triageMsg: '',
      repos: [], runner: { running: null, queued: 0 },
      backends: [], backendsHome: '/data/home', authModal: null,
      settings: { defaults: { backend: 'litellm', model: '', base_url: '', max_turns: '',
        temperature: '', timeout: '', agent_cmd: '', agent_output: '', extra_args: '', env: [] },
        max_concurrent_scans: 1 },
      settingsMsg: '',
      editing: null, repoForm: null, formErr: '',
      current: null,          // repo detail
      finding: null,          // finding detail (advisory)
      scans: [], scanView: null,
      sort: {},               // { tableName: { key, dir } } — click-to-sort per table
      poll: null, clock: null, nowTs: Date.now(),
      menuOpen: false,        // mobile nav drawer
    };
  },
  computed: {
    filteredFindings() {
      return this.findings.filter(f =>
        (!this.findingFilter.status || f.status === this.findingFilter.status));
    },
    activeScans() { return (this.scans || []).filter(s => ['queued', 'running'].includes(s.status)); },
    recentScans() { return (this.scans || []).slice(0, 6); },
  },
  methods: {
    async api(method, path, body) {
      const opt = { method, headers: {}, credentials: 'same-origin' };
      if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
      const r = await fetch(path, opt);
      if (r.status === 401) { this.me = null; throw new Error('unauthorized'); }
      if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || r.statusText); }
      return r.status === 204 ? null : r.json();
    },
    async doLogin() {
      this.login.err = '';
      try {
        const fd = new URLSearchParams({ username: this.login.username, password: this.login.password });
        const r = await fetch('/api/login', { method: 'POST', body: fd, credentials: 'same-origin' });
        if (!r.ok) { this.login.err = 'Invalid credentials'; return; }
        const d = await r.json();
        this.me = { username: d.username, must_change: d.must_change };
        this.login.password = '';
        if (d.must_change) this.pw.show = true;
        this.go('dashboard');
      } catch (e) { this.login.err = String(e.message || e); }
    },
    async logout() { await this.api('POST', '/api/logout'); this.me = null; },
    async changePw() {
      this.pw.err = ''; this.pw.msg = '';
      try {
        await this.api('POST', '/api/change-password', { current: this.pw.current, new: this.pw.next });
        this.pw.msg = 'Password changed.'; this.pw.current = ''; this.pw.next = '';
        this.me.must_change = false; setTimeout(() => (this.pw.show = false), 800);
      } catch (e) { this.pw.err = String(e.message || e); }
    },
    go(view) {
      this.view = view; this.finding = null; this.current = null; this.scanView = null;
      this.menuOpen = false;
      if (view === 'dashboard') this.loadDashboard();
      if (view === 'repos') this.loadRepos();
      if (view === 'findings') this.loadFindings();
      if (view === 'scans') this.loadScans();
      if (view === 'backends') this.loadBackends();
      if (view === 'settings') { this.loadSettings(); this.loadBackends(); }
    },
    async loadDashboard() {
      const d = await this.api('GET', '/api/findings?status=open');
      this.findings = d.findings; this.counts = d.counts;
      await this.loadRepos();
      await this.loadScans();
    },
    async loadRepos() {
      const d = await this.api('GET', '/api/repos'); this.repos = d.repos; this.runner = d.runner;
    },
    async loadFindings() {
      const q = new URLSearchParams();
      if (this.findingFilter.status) q.set('status', this.findingFilter.status);
      if (this.findingFilter.min_sev) q.set('min_sev', this.findingFilter.min_sev);
      const d = await this.api('GET', '/api/findings?' + q.toString());
      this.findings = d.findings; this.counts = d.counts;
    },
    async loadBackends() {
      const d = await this.api('GET', '/api/backends');
      this.backends = d.backends; this.backendsHome = d.home || this.backendsHome;
    },
    async loadSettings() {
      const s = await this.api('GET', '/api/settings');
      if (!s.defaults) s.defaults = {};
      if (!Array.isArray(s.defaults.env)) s.defaults.env = [];
      // Secrets arrive masked by default; _show is a per-row reveal toggle (UI-only).
      s.defaults.env.forEach(e => { e._show = false; });
      this.settings = s;
    },
    async saveSettings() {
      // Strip UI-only reveal flags so only {key,value} is persisted/sent to scans.
      const payload = JSON.parse(JSON.stringify(this.settings));
      (payload.defaults.env || []).forEach(e => { delete e._show; });
      await this.api('PUT', '/api/settings', payload);
      this.settingsMsg = 'Saved.'; setTimeout(() => (this.settingsMsg = ''), 1500);
    },
    addEnv(list) { list.push({ key: '', value: '', _show: true }); },
    rmEnv(list, i) { list.splice(i, 1); },

    // in-browser authorization terminal (xterm.js <-> PTY over WebSocket)
    canAuth(b) { return b.available && ['claude-code', 'codex', 'gemini'].includes(b.name); },
    openAuth(b) { this.authModal = b.name; this.$nextTick(() => this.initTerm(b.name)); },
    initTerm(backend) {
      const el = this.$refs.termEl;
      if (!el || !window.Terminal) { return; }
      const term = new window.Terminal({ cursorBlink: true, fontSize: 13,
        theme: { background: '#0d1117', foreground: '#d6dee8' } });
      let fit = null;
      try { fit = new FitAddon.FitAddon(); term.loadAddon(fit); } catch (e) {}
      term.open(el);
      try { if (fit) fit.fit(); } catch (e) {}
      const proto = location.protocol === 'https:' ? 'wss' : 'ws';
      const ws = new WebSocket(proto + '://' + location.host + '/ws/auth?backend=' + encodeURIComponent(backend));
      ws.onopen = () => {
        const send = () => { try { ws.send('\x00resize:' + term.cols + ',' + term.rows); } catch (e) {} };
        term.onData(d => { try { ws.send(d); } catch (e) {} });
        term.onResize(send); send(); term.focus();
      };
      ws.onmessage = e => term.write(e.data);
      ws.onclose = () => { try { term.write('\r\n[disconnected]\r\n'); } catch (e) {} };
      this._term = term; this._ws = ws; this._fit = fit;
      this._onResize = () => { try { if (fit) fit.fit(); } catch (e) {} };
      window.addEventListener('resize', this._onResize);
    },
    closeAuth() {
      try { if (this._ws) this._ws.close(); } catch (e) {}
      try { if (this._term) this._term.dispose(); } catch (e) {}
      if (this._onResize) window.removeEventListener('resize', this._onResize);
      this._term = this._ws = this._fit = this._onResize = null;
      this.authModal = null; this.loadBackends();
    },

    // A repository only carries WHAT to scan + how often + context. The AI (backend,
    // model, keys, args) is one global template in Settings, applied to every scan.
    newRepo() {
      this.editing = 'new'; this.formErr = '';
      this.repoForm = { url: '', name: '', cron: '', context: '', enabled: true };
    },
    editRepo(r) {
      this.editing = r.id; this.formErr = '';
      this.repoForm = { id: r.id, url: r.url, name: r.name || '', cron: r.cron || '',
        context: r.context || '', enabled: !!r.enabled };
    },
    async saveRepo() {
      this.formErr = '';
      try {
        if (this.editing === 'new') await this.api('POST', '/api/repos', this.repoForm);
        else await this.api('PUT', '/api/repos/' + this.editing, this.repoForm);
        this.editing = null; this.repoForm = null; await this.loadRepos();
      } catch (e) { this.formErr = String(e.message || e); }
    },
    async deleteRepo(r) {
      if (!confirm('Delete ' + r.slug + ' and its findings?')) return;
      await this.api('DELETE', '/api/repos/' + r.id); await this.loadRepos();
    },
    async runScan(r) { await this.api('POST', '/api/repos/' + r.id + '/scan'); await this.loadRepos(); this.go('scans'); },

    async openRepo(r) {
      const d = await this.api('GET', '/api/repos/' + r.id);
      this.current = d; this.view = 'repo'; this.finding = null;
    },
    async openFinding(f) {
      const d = await this.api('GET', '/api/findings/' + encodeURIComponent(f.uuid || f.id));
      this.finding = d.finding;
      this.finding._md = d.advisory_markdown;
      this.finding._comments = d.comments || [];
      this.finding._triageValues = d.triage_values || Object.keys(TRIAGE_LABELS);
      this.finding._triageLabels = d.triage_labels || TRIAGE_LABELS;
      this.commentDraft = ''; this.triageMsg = '';
    },
    async saveTriage() {
      await this.api('PUT', '/api/findings/' + encodeURIComponent(this.finding.uuid) + '/triage',
        { triage: this.finding.triage || 'unset', note: this.finding.triage_note || '' });
      this.finding.triaged_by = this.me.username; this.finding.triaged_at = new Date().toISOString();
      this.triageMsg = 'Saved — future scans will see this.'; setTimeout(() => (this.triageMsg = ''), 2500);
    },
    async addComment() {
      const body = (this.commentDraft || '').trim();
      if (!body) return;
      const d = await this.api('POST', '/api/findings/' + encodeURIComponent(this.finding.uuid) + '/comments', { body });
      this.finding._comments.push(d.comment); this.commentDraft = '';
    },
    triageLabel(t) { return TRIAGE_LABELS[t] || t; },
    triageShort(t) { return TRIAGE_SHORT[t] || t; },
    triageFiltered(list) {
      const t = this.findingFilter.triage;
      if (!t) return list;
      if (t === 'triaged') return list.filter(f => f.triage && f.triage !== 'unset');
      if (t === 'unset') return list.filter(f => !f.triage || f.triage === 'unset');
      return list.filter(f => f.triage === t);
    },
    async loadScans() {
      const d = await this.api('GET', '/api/scans'); this.scans = d.scans; this.runner = d.runner;
    },
    async openScan(s) {
      const el = this.$refs.logEl;
      // remember whether the user is pinned to the bottom BEFORE we replace content
      const atBottom = !el || (el.scrollHeight - el.scrollTop - el.clientHeight < 40);
      this.scanView = await this.api('GET', '/api/scans/' + s.id);
      if (atBottom) this.$nextTick(() => { const e = this.$refs.logEl; if (e) e.scrollTop = e.scrollHeight; });
    },
    async relaunchScan(s) {
      const d = await this.api('POST', '/api/scans/' + s.id + '/relaunch');
      await this.loadScans();
      if (d && d.scan_id) this.openScan({ id: d.scan_id });   // follow the fresh run live
    },
    async deleteScan(s) {
      if (['queued', 'running'].includes(s.status)) { alert('This scan is still ' + s.status + ' — stop it before deleting.'); return; }
      if (!confirm('Delete scan #' + s.id + '? (findings are kept)')) return;
      await this.api('DELETE', '/api/scans/' + s.id);
      if (this.scanView && this.scanView.id === s.id) this.scanView = null;
      await this.loadScans();
      if (this.current) this.openRepo(this.current.repo);   // refresh repo scan history if open
    },
    async openFindingFromScan(f) {
      this.scanView = null;                 // leave the log modal
      if (this.view !== 'findings') this.view = 'findings';
      await this.openFinding(f); this.view = 'finding';
    },
    isLive(s) { return s && ['queued', 'running'].includes(s.status); },
    heartbeatText(s) {
      if (!s || s.status !== 'running') return '';
      const ts = s.heartbeat || s.started;
      if (!ts) return 'live';
      const secs = Math.max(0, Math.round((this.nowTs - Date.parse(ts)) / 1000));
      return 'live · last output ' + (secs < 1 ? 'just now' : secs + 's ago');
    },
    pdf(url) { window.open(url, '_blank'); },
    fmt(t) { return t ? t.replace('T', ' ').replace('Z', '') : ''; },
    money(v) { const n = Number(v) || 0; return '$' + (n < 1 && n > 0 ? n.toFixed(3) : n.toFixed(2)); },
    sevList(by) { return SEV.filter(s => by && by[s]).map(s => s + ':' + by[s]).join('  '); },
    cronText(expr) {
      const s = (expr || '').trim();
      if (!s) return 'No schedule — this repository is only scanned when you click Scan.';
      const p = s.split(/\s+/);
      if (p.length !== 5) return '⚠ Invalid cron — expected 5 fields: minute hour day-of-month month day-of-week.';
      const [mi, ho, dom, mon, dow] = p;
      const DOW = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
      const MON = ['', 'January', 'February', 'March', 'April', 'May', 'June', 'July',
        'August', 'September', 'October', 'November', 'December'];
      const step = f => { const m = String(f).match(/^\*\/(\d+)$/); return m ? +m[1] : null; };
      let time;
      if (mi === '*' && ho === '*') time = 'every minute';
      else if (step(mi) && ho === '*') time = 'every ' + step(mi) + ' minutes';
      else if (ho === '*') time = 'every hour at minute ' + mi;
      else if (/^\d+$/.test(ho) && /^\d+$/.test(mi))
        time = 'at ' + String(ho).padStart(2, '0') + ':' + String(mi).padStart(2, '0');
      else time = 'at minute ' + mi + ' of hour ' + ho;
      const nameDow = d => {
        const r = String(d).match(/^(\d)-(\d)$/);
        if (r) return DOW[+r[1] % 7] + '–' + DOW[+r[2] % 7];
        return /^\d$/.test(d) ? DOW[+d % 7] : d;
      };
      const dowStr = dow !== '*' ? 'on ' + dow.split(',').map(nameDow).join(', ') : '';
      const domStr = dom !== '*' ? 'on day ' + dom + ' of the month' : '';
      const monStr = mon !== '*' ? ' in ' + mon.split(',').map(m => /^\d+$/.test(m) ? (MON[+m] || m) : m).join(', ') : '';
      const when = (dowStr && domStr) ? domStr + ' and ' + dowStr : (dowStr || domStr || 'every day');
      return 'Runs ' + time + ', ' + when + monStr + ' (UTC).';
    },

    // click-to-sort, shared by every table
    toggleSort(tbl, key) {
      const s = this.sort[tbl] || {};
      this.sort[tbl] = (s.key === key) ? { key, dir: -(s.dir || 1) } : { key, dir: 1 };
    },
    caret(tbl, key) {
      const s = this.sort[tbl];
      return s && s.key === key ? (s.dir > 0 ? ' ▲' : ' ▼') : '';
    },
    sortRows(list, tbl) {
      const s = this.sort[tbl];
      if (!s || !s.key) return list;
      const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      const k = s.key, dir = s.dir;
      return [...(list || [])].sort((a, b) => {
        let av = a[k], bv = b[k];
        if (k === 'severity') { av = rank[av] || 0; bv = rank[bv] || 0; }
        if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir;
        av = (av == null ? '' : String(av)).toLowerCase();
        bv = (bv == null ? '' : String(bv)).toLowerCase();
        return av < bv ? -dir : av > bv ? dir : 0;
      });
    },

    tick() {
      // light polling while scans are active or on scan/repo/dashboard views
      if (!this.me) { this.scheduleTick(); return; }
      const liveOpen = this.isLive(this.scanView);
      if (this.view === 'scans') this.loadScans().catch(() => {});
      else if (this.view === 'dashboard') { this.loadScans().catch(() => {}); this.loadRepos().catch(() => {}); }
      if (liveOpen) this.openScan(this.scanView).catch(() => {});
      this.scheduleTick();
    },
    anyLive() { return this.isLive(this.scanView) || ((this.runner && this.runner.running_count) > 0); },
    scheduleTick() {
      // fast cadence (1.5s) whenever a scan is live (log modal open OR any running), else easy (4s)
      const delay = this.anyLive() ? 1500 : 4000;
      this.poll = setTimeout(() => this.tick(), delay);
    },
  },
  async mounted() {
    try { this.me = await this.api('GET', '/api/me'); if (this.me.must_change) this.pw.show = true; this.go('dashboard'); }
    catch (e) { this.me = null; }
    this.ready = true;
    this.scheduleTick();
    this.clock = setInterval(() => { this.nowTs = Date.now(); }, 1000);
  },
  template: `
<div v-if="!ready"></div>

<!-- LOGIN -->
<div v-else-if="!me" class="login">
  <div class="brand" style="font-size:22px">security <b>forge</b><small>continuous security scanning</small></div>
  <div class="card">
    <label>Username</label><input v-model="login.username" @keyup.enter="doLogin">
    <label>Password</label><input type="password" v-model="login.password" @keyup.enter="doLogin">
    <div class="err" v-if="login.err">{{login.err}}</div>
    <div style="margin-top:14px"><button class="primary" style="width:100%" @click="doLogin">Sign in</button></div>
    <div class="muted" style="margin-top:10px;font-size:12px">Default: root / root — you'll be asked to change it.</div>
  </div>
</div>

<!-- APP -->
<div v-else class="wrap" :class="{'menu-open':menuOpen}">
  <div v-if="menuOpen" class="side-backdrop" @click="menuOpen=false"></div>
  <div class="side" :class="{open:menuOpen}">
    <div class="brand">security <b>forge</b><small>{{me.username}}</small></div>
    <div class="nav">
      <a :class="{on:view=='dashboard'}" @click="go('dashboard')">Dashboard</a>
      <a :class="{on:view=='repos'||view=='repo'}" @click="go('repos')">Repositories</a>
      <a :class="{on:view=='findings'||view=='finding'}" @click="go('findings')">Findings</a>
      <a :class="{on:view=='scans'}" @click="go('scans')">Scans</a>
      <a :class="{on:view=='backends'}" @click="go('backends')">Backends</a>
      <a :class="{on:view=='settings'}" @click="go('settings')">Settings</a>
      <a class="signout" @click="logout">Sign out</a>
    </div>
  </div>

  <div class="main">
    <div class="top">
      <button class="hamburger" @click="menuOpen=!menuOpen" aria-label="Menu">☰</button>
      <h1 style="text-transform:capitalize">{{ finding ? 'Advisory' : (current ? current.repo.slug : view) }}</h1>
      <div class="flex muted" style="font-size:12px">
        <span><span class="dot" :class="runner.running_count?'on':'off'"></span>{{runner.running_count||0}}/{{runner.max||1}} scanning</span>
        <span v-if="runner.queued">· {{runner.queued}} queued</span>
      </div>
    </div>

    <!-- DASHBOARD -->
    <div v-if="view=='dashboard'">
      <div class="card">
        <span class="stat"><b>{{counts.repos||0}}</b><span>repositories</span></span>
        <span class="stat"><b>{{counts.open||0}}</b><span>open findings</span></span>
        <span class="stat"><b>{{counts.mitigated||0}}</b><span>mitigated</span></span>
        <span class="stat" v-for="s in ['CRITICAL','HIGH','MEDIUM']" :key="s">
          <b><span class="badge" :class="'b-'+s">{{(counts.by_severity||{})[s]||0}}</span></b><span>{{s.toLowerCase()}}</span></span>
        <span class="stat"><b>{{counts.scans||0}}</b><span>scans</span></span>
        <span class="stat"><b>{{money(counts.cost_usd)}}</b><span>total spend</span></span>
        <button class="primary" style="float:right" @click="pdf('/api/report.pdf')">Executive PDF (all)</button>
      </div>
      <div class="card">
        <div class="flex"><h2 style="margin-top:0">{{activeScans.length ? 'Active scans' : 'Recent scans'}}</h2>
          <span v-if="activeScans.length" class="live" style="font-size:13px"><span class="dot pulse on"></span>{{runner.running_count||0}} running<span v-if="runner.queued">, {{runner.queued}} queued</span></span>
          <span class="spacer"></span><a @click="go('scans')">all scans →</a></div>
        <table><thead><tr>
          <th>#</th><th>Project</th><th>Status</th><th>New</th><th>Cost</th><th>Started</th></tr></thead>
        <tbody>
          <tr v-for="s in (activeScans.length ? activeScans : recentScans)" :key="s.id" style="cursor:pointer" @click="openScan(s)">
            <td>{{s.id}}</td><td class="muted">{{s.slug}}</td>
            <td><span class="pill" :class="s.status"><span v-if="isLive(s)" class="dot pulse on"></span>{{s.status}}</span>
              <span v-if="s.status==='running'" class="live nowrap" style="font-size:12px;margin-left:6px">{{heartbeatText(s)}}</span></td>
            <td>{{s.new_count}}</td><td class="nowrap">{{money(s.cost_usd)}}</td>
            <td class="muted nowrap">{{fmt(s.started)}}</td></tr>
          <tr v-if="!scans.length"><td colspan="6" class="muted">No scans yet — add a repository and click Scan.</td></tr>
        </tbody></table>
      </div>
      <div class="card">
        <h2>Open findings</h2>
        <table><thead><tr>
          <th @click="toggleSort('dash','severity')" style="cursor:pointer">Sev{{caret('dash','severity')}}</th>
          <th @click="toggleSort('dash','slug')" style="cursor:pointer">Project{{caret('dash','slug')}}</th>
          <th @click="toggleSort('dash','title')" style="cursor:pointer">Title{{caret('dash','title')}}</th>
          <th @click="toggleSort('dash','file')" style="cursor:pointer">Where{{caret('dash','file')}}</th></tr></thead>
        <tbody><tr v-for="f in sortRows(findings,'dash').slice(0,25)" :key="f.id" @click="openFinding(f); view='finding'" style="cursor:pointer">
          <td><span class="badge" :class="'b-'+f.severity">{{f.severity}}</span></td>
          <td class="muted">{{f.slug}}</td><td>{{f.title}}</td>
          <td class="mono muted">{{f.file}}{{f.line?':'+f.line:''}}</td></tr>
          <tr v-if="!findings.length"><td colspan="4" class="muted">No open findings.</td></tr></tbody></table>
      </div>
    </div>

    <!-- REPOS -->
    <div v-if="view=='repos'">
      <div class="flex" style="margin-bottom:10px"><span class="muted" style="font-size:12px">All scans use the global AI configuration (<a @click="go('settings')">Settings</a>).</span><span class="spacer"></span><button class="primary" @click="newRepo">+ Add repository</button></div>
      <div class="card"><table>
        <thead><tr>
          <th @click="toggleSort('repos','slug')" style="cursor:pointer">Repository{{caret('repos','slug')}}</th>
          <th @click="toggleSort('repos','cron')" style="cursor:pointer">Schedule{{caret('repos','cron')}}</th>
          <th @click="toggleSort('repos','next_run')" style="cursor:pointer">Next run{{caret('repos','next_run')}}</th>
          <th @click="toggleSort('repos','open_findings')" style="cursor:pointer">Open{{caret('repos','open_findings')}}</th>
          <th @click="toggleSort('repos','last_status')" style="cursor:pointer">Last{{caret('repos','last_status')}}</th><th></th></tr></thead>
        <tbody>
          <tr v-for="r in sortRows(repos,'repos')" :key="r.id">
            <td><a @click="openRepo(r)">{{r.slug}}</a><div class="muted" v-if="!r.enabled">disabled</div></td>
            <td class="mono muted">{{r.cron||'—'}}</td>
            <td class="muted nowrap">{{fmt(r.next_run)||'—'}}</td>
            <td><b>{{r.open_findings}}</b> <span class="muted" style="font-size:11px">{{sevList(r.by_severity)}}</span></td>
            <td><span class="pill" :class="r.last_status">{{r.last_status||'never'}}</span></td>
            <td class="nowrap right">
              <button class="sm" @click="runScan(r)">Scan</button>
              <button class="sm" @click="editRepo(r)">Edit</button>
              <button class="sm danger" @click="deleteRepo(r)">✕</button></td>
          </tr>
          <tr v-if="!repos.length"><td colspan="6" class="muted">No repositories yet. Add one to start continuous scanning.</td></tr>
        </tbody></table></div>
    </div>

    <!-- REPO DETAIL -->
    <div v-if="view=='repo' && current">
      <div style="margin-bottom:10px"><a @click="go('repos')">← repositories</a></div>
      <div class="card">
        <div class="flex"><b>{{current.repo.url}}</b><span class="spacer"></span>
          <button class="sm" @click="editRepo(current.repo)">Edit</button>
          <button class="sm primary" @click="runScan(current.repo)">Scan now</button>
          <button class="sm" @click="pdf('/api/report.pdf?repo_id='+current.repo.id)">Executive PDF</button></div>
        <div class="muted" style="margin-top:8px">cron {{current.repo.cron||'—'}} · next {{fmt(current.next_run)||'—'}} · {{current.repo.enabled?'enabled':'disabled'}}</div>
        <div v-if="current.repo.context" style="margin-top:8px"><span class="muted">context:</span> {{current.repo.context}}</div>
      </div>
      <div class="card"><h2>Findings</h2><table>
        <thead><tr>
          <th @click="toggleSort('rfind','severity')" style="cursor:pointer">Sev{{caret('rfind','severity')}}</th>
          <th @click="toggleSort('rfind','title')" style="cursor:pointer">Title{{caret('rfind','title')}}</th>
          <th @click="toggleSort('rfind','file')" style="cursor:pointer">Where{{caret('rfind','file')}}</th>
          <th @click="toggleSort('rfind','status')" style="cursor:pointer">Status{{caret('rfind','status')}}</th></tr></thead>
        <tbody><tr v-for="f in sortRows(current.findings,'rfind')" :key="f.id" style="cursor:pointer" @click="openFinding(f); view='finding'">
          <td><span class="badge" :class="'b-'+f.severity">{{f.severity}}</span></td>
          <td>{{f.title}}</td><td class="mono muted">{{f.file}}{{f.line?':'+f.line:''}}</td>
          <td><span class="pill" :class="f.status">{{f.status}}</span></td></tr>
          <tr v-if="!current.findings.length"><td colspan="4" class="muted">No findings recorded yet.</td></tr></tbody></table></div>
      <div class="card"><h2>Scan history</h2><table>
        <thead><tr>
          <th @click="toggleSort('rscan','id')" style="cursor:pointer">#{{caret('rscan','id')}}</th>
          <th @click="toggleSort('rscan','trigger')" style="cursor:pointer">Trigger{{caret('rscan','trigger')}}</th>
          <th @click="toggleSort('rscan','status')" style="cursor:pointer">Status{{caret('rscan','status')}}</th>
          <th @click="toggleSort('rscan','new_count')" style="cursor:pointer">New{{caret('rscan','new_count')}}</th>
          <th @click="toggleSort('rscan','mitigated_count')" style="cursor:pointer">Mitigated{{caret('rscan','mitigated_count')}}</th>
          <th @click="toggleSort('rscan','cost_usd')" style="cursor:pointer">Cost{{caret('rscan','cost_usd')}}</th>
          <th @click="toggleSort('rscan','started')" style="cursor:pointer">Started{{caret('rscan','started')}}</th><th></th></tr></thead>
        <tbody><tr v-for="s in sortRows(current.scans,'rscan')" :key="s.id" style="cursor:pointer" @click="openScan(s)">
          <td>{{s.id}}</td><td class="muted">{{s.trigger}}</td>
          <td><span class="pill" :class="s.status"><span v-if="isLive(s)" class="dot pulse on"></span>{{s.status}}</span></td>
          <td>{{s.new_count}}</td><td>{{s.mitigated_count}}</td><td class="nowrap">{{money(s.cost_usd)}}</td><td class="muted nowrap">{{fmt(s.started)}}</td>
          <td class="nowrap right">
            <button class="sm" @click.stop="relaunchScan(s)">Relaunch</button>
            <button class="sm danger" :disabled="isLive(s)" @click.stop="deleteScan(s)">✕</button></td></tr></tbody></table></div>
    </div>

    <!-- FINDINGS (global) -->
    <div v-if="view=='findings'">
      <div class="card flex">
        <label style="margin:0">Status</label>
        <select style="width:auto" v-model="findingFilter.status" @change="loadFindings"><option value="">all</option><option value="open">open</option><option value="mitigated">mitigated</option></select>
        <label style="margin:0">Min severity</label>
        <select style="width:auto" v-model="findingFilter.min_sev" @change="loadFindings"><option value="">any</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select>
        <label style="margin:0">Triage</label>
        <select style="width:auto" v-model="findingFilter.triage">
          <option value="">all</option><option value="unset">untriaged</option><option value="triaged">any triaged</option>
          <option value="confirmed">confirmed</option><option value="false_positive">false positive</option>
          <option value="accepted_risk">accepted risk</option><option value="wont_fix">won't fix</option><option value="duplicate">duplicate</option></select>
        <span class="spacer"></span><span class="muted">{{triageFiltered(findings).length}} findings</span>
      </div>
      <div class="card"><table>
        <thead><tr>
          <th @click="toggleSort('findings','severity')" style="cursor:pointer">Sev{{caret('findings','severity')}}</th>
          <th @click="toggleSort('findings','slug')" style="cursor:pointer">Project{{caret('findings','slug')}}</th>
          <th @click="toggleSort('findings','title')" style="cursor:pointer">Title{{caret('findings','title')}}</th>
          <th @click="toggleSort('findings','file')" style="cursor:pointer">Where{{caret('findings','file')}}</th>
          <th @click="toggleSort('findings','status')" style="cursor:pointer">Status{{caret('findings','status')}}</th>
          <th @click="toggleSort('findings','last_seen')" style="cursor:pointer">Seen{{caret('findings','last_seen')}}</th></tr></thead>
        <tbody><tr v-for="f in sortRows(triageFiltered(findings),'findings')" :key="f.id" style="cursor:pointer" @click="openFinding(f); view='finding'">
          <td><span class="badge" :class="'b-'+f.severity">{{f.severity}}</span></td>
          <td class="muted">{{f.slug}}</td><td>{{f.title}}</td>
          <td class="mono muted">{{f.file}}{{f.line?':'+f.line:''}}</td>
          <td><span class="pill" :class="f.status">{{f.status}}</span>
            <span v-if="f.triage && f.triage!=='unset'" class="tri" :class="'tri-'+f.triage">{{triageShort(f.triage)}}</span></td>
          <td class="muted nowrap">{{fmt(f.last_seen)}}</td></tr>
          <tr v-if="!triageFiltered(findings).length"><td colspan="6" class="muted">No findings.</td></tr></tbody></table></div>
    </div>

    <!-- FINDING DETAIL (advisory) -->
    <div v-if="view=='finding' && finding">
      <div class="flex" style="margin-bottom:10px"><a @click="go('findings')">← findings</a><span class="spacer"></span>
        <span class="pill" :class="finding.status">{{finding.status}}</span>
        <span v-if="finding.triage && finding.triage!=='unset'" class="tri" :class="'tri-'+finding.triage">{{triageShort(finding.triage)}}</span>
        <button class="sm primary" @click="pdf('/api/findings/'+encodeURIComponent(finding.uuid||finding.id)+'/advisory.pdf')">Download PDF</button></div>

      <!-- TRIAGE -->
      <div class="card">
        <h2 style="margin-top:0">Triage</h2>
        <div class="muted" style="font-size:13px;margin-bottom:6px">Your decision persists across rescans and is fed into future scans as authoritative context — mark a false positive here and the agent is told not to re-report it.</div>
        <div style="max-width:280px"><label>Disposition</label>
          <select v-model="finding.triage"><option v-for="t in finding._triageValues" :key="t" :value="t">{{finding._triageLabels[t]||t}}</option></select></div>
        <label>Reason / justification (why — this text is sent to future scans)</label>
        <textarea v-model="finding.triage_note" placeholder="e.g. Endpoint is internal-only and not reachable from the internet. / Input is validated upstream in middleware X. / Accepted risk, tracked in JIRA-123."></textarea>
        <div style="margin-top:10px"><button class="primary" @click="saveTriage">Save triage</button>
          <span class="ok" v-if="triageMsg">{{triageMsg}}</span>
          <span class="muted" style="font-size:12px;margin-left:8px" v-if="finding.triaged_by">last set by {{finding.triaged_by}} · {{fmt(finding.triaged_at)}}</span></div>
      </div>

      <!-- COMMENTS -->
      <div class="card">
        <h2 style="margin-top:0">Comments</h2>
        <div v-if="!finding._comments || !finding._comments.length" class="muted" style="margin-bottom:10px">No comments yet.</div>
        <div v-for="c in finding._comments" :key="c.id" class="comment">
          <div class="muted" style="font-size:12px">{{c.author}} · {{fmt(c.created)}}</div>
          <div style="white-space:pre-wrap">{{c.body}}</div></div>
        <textarea v-model="commentDraft" placeholder="Add a comment — context, triage rationale, notes for the next reviewer…" @keydown.ctrl.enter="addComment"></textarea>
        <div style="margin-top:8px"><button class="primary" @click="addComment">Comment</button>
          <span class="muted" style="font-size:12px;margin-left:8px">Ctrl+Enter</span></div>
      </div>

      <div class="card"><h2 style="margin-top:0">Advisory</h2><pre>{{finding._md}}</pre></div>
    </div>

    <!-- SCANS -->
    <div v-if="view=='scans'">
      <div class="card"><table>
        <thead><tr>
          <th @click="toggleSort('scans','id')" style="cursor:pointer">#{{caret('scans','id')}}</th>
          <th @click="toggleSort('scans','slug')" style="cursor:pointer">Project{{caret('scans','slug')}}</th>
          <th @click="toggleSort('scans','trigger')" style="cursor:pointer">Trigger{{caret('scans','trigger')}}</th>
          <th @click="toggleSort('scans','status')" style="cursor:pointer">Status{{caret('scans','status')}}</th>
          <th @click="toggleSort('scans','new_count')" style="cursor:pointer">New{{caret('scans','new_count')}}</th>
          <th @click="toggleSort('scans','mitigated_count')" style="cursor:pointer">Mit.{{caret('scans','mitigated_count')}}</th>
          <th @click="toggleSort('scans','total_count')" style="cursor:pointer">Open{{caret('scans','total_count')}}</th>
          <th @click="toggleSort('scans','cost_usd')" style="cursor:pointer">Cost{{caret('scans','cost_usd')}}</th>
          <th @click="toggleSort('scans','started')" style="cursor:pointer">Started{{caret('scans','started')}}</th><th></th></tr></thead>
        <tbody><tr v-for="s in sortRows(scans,'scans')" :key="s.id" style="cursor:pointer" @click="openScan(s)">
          <td>{{s.id}}</td><td class="muted">{{s.slug}}</td><td class="muted">{{s.trigger}}</td>
          <td><span class="pill" :class="s.status"><span v-if="isLive(s)" class="dot pulse on"></span>{{s.status}}</span></td>
          <td>{{s.new_count}}</td><td>{{s.mitigated_count}}</td><td>{{s.total_count}}</td>
          <td class="nowrap">{{money(s.cost_usd)}}</td>
          <td class="muted nowrap">{{fmt(s.started)}}</td>
          <td class="nowrap right">
            <button class="sm" @click.stop="relaunchScan(s)">Relaunch</button>
            <button class="sm danger" :disabled="isLive(s)" @click.stop="deleteScan(s)">✕</button></td></tr>
          <tr v-if="!scans.length"><td colspan="10" class="muted">No scans yet.</td></tr></tbody></table></div>
    </div>

    <!-- BACKENDS -->
    <div v-if="view=='backends'">
      <div class="card"><h2>Available backends / tools</h2><table>
        <thead><tr>
          <th @click="toggleSort('backends','name')" style="cursor:pointer">Backend{{caret('backends','name')}}</th>
          <th @click="toggleSort('backends','available')" style="cursor:pointer">Installed{{caret('backends','available')}}</th>
          <th @click="toggleSort('backends','authorized')" style="cursor:pointer">Authorized{{caret('backends','authorized')}}</th>
          <th>Authorize / key</th></tr></thead>
        <tbody><tr v-for="b in sortRows(backends,'backends')" :key="b.name">
          <td class="mono">{{b.name}}<div class="muted" style="font-size:11px">{{b.kind}}</div></td>
          <td><span class="dot" :class="b.available?'on':'off'"></span>{{b.available?'yes':'no'}}</td>
          <td><span v-if="b.authorized===null" class="muted">n/a</span>
              <span v-else><span class="dot" :class="b.authorized?'on':'off'"></span>{{b.authorized?'yes':'no'}}</span></td>
          <td style="font-size:12px">
            <button v-if="canAuth(b)" class="sm primary" @click="openAuth(b)">{{b.authorized?'Re-authorize':'Authorize'}} in browser</button>
            <div class="mono muted" style="margin-top:4px">{{b.authorize}}</div></td></tr></tbody></table>
        <div class="muted" style="margin-top:10px">
          Authorize a CLI backend by logging in <b>inside the container</b> — credentials persist on the data volume at <span class="mono">{{backendsHome}}</span>, so you only do it once. Copy the command above and replace <span class="mono">&lt;container&gt;</span> with your container name (e.g. <span class="mono">docker exec -it security-forge-ui claude</span>). Or provide provider API keys as env vars — per repo (in its form) or to the container. Verification is OFF here — static analysis only.
        </div>
      </div>
    </div>

    <!-- SETTINGS -->
    <div v-if="view=='settings'">
      <div class="card"><h2>Concurrency</h2>
        <div style="max-width:240px"><label>Max orchestrators at a time</label>
          <input type="number" min="1" v-model.number="settings.max_concurrent_scans"></div>
        <div class="muted" style="font-size:12px;margin-top:6px">How many repositories scan in parallel. Each scan is a full orchestrator + LLM session — raise it only if the host can handle it.</div>
        <div style="margin-top:12px"><button class="primary" @click="saveSettings">Save</button> <span class="ok" v-if="settingsMsg">{{settingsMsg}}</span></div>
      </div>
      <div class="card"><h2>AI configuration — one template for all repositories</h2>
        <div class="muted" style="font-size:12px;margin-bottom:8px">Backend, model, keys and args used for <b>every</b> scan. Repositories only choose what to scan, when, and their context.</div>
        <div class="row">
          <div><label>Backend</label><select v-model="settings.defaults.backend"><option v-for="b in backends" :key="b.name" :value="b.name">{{b.name}}{{b.available?'':' (not installed)'}}</option></select></div>
          <div><label>Model</label><input v-model="settings.defaults.model" placeholder="openai/gpt-5, anthropic/claude-..., ollama/llama3"></div></div>
        <div class="row"><div><label>Base URL</label><input class="mono" v-model="settings.defaults.base_url" placeholder="http://localhost:4000"></div>
          <div><label>Timeout — seconds per scan (0 = no limit)</label><input class="mono" v-model="settings.defaults.timeout" placeholder="0"></div></div>
        <div class="row"><div><label>Max turns</label><input class="mono" v-model="settings.defaults.max_turns" placeholder="500"></div>
          <div><label>Temperature</label><input class="mono" v-model="settings.defaults.temperature"></div></div>
        <div class="muted" style="font-size:12px;margin-top:6px">
          <b>Timeout</b>: seconds before a scan is stopped — <b>0 = no limit</b> (default; let the scan run to completion). ·
          <b>Max turns</b>: how many tool-use steps (LLM round-trips) the agent may take in one scan — the main safety bound when there's no timeout; blank = 500. ·
          <b>Base URL</b>: point at a self-hosted/OpenAI-compatible endpoint or LiteLLM proxy. ·
          <b>Temperature</b>: sampling randomness; blank = the model's default.
        </div>
        <label>Extra orchestrator args</label><input class="mono" v-model="settings.defaults.extra_args">
        <label>Environment — provider keys / base URLs (sent to every scan)</label>
        <div class="muted" style="font-size:12px;margin-bottom:6px">Values are hidden by default. Use the eye to reveal one while editing.</div>
        <div v-for="(e,i) in settings.defaults.env" :key="i" class="flex" style="margin-bottom:6px">
          <input class="mono" style="flex:1" v-model="e.key" placeholder="OPENAI_API_KEY" autocomplete="off" autocapitalize="off" spellcheck="false">
          <input class="mono" style="flex:2" v-model="e.value" placeholder="sk-..." :type="e._show?'text':'password'" autocomplete="off" autocapitalize="off" spellcheck="false">
          <button class="sm" type="button" @click="e._show=!e._show" :title="e._show?'Hide':'Reveal'">{{e._show?'🙈':'👁'}}</button>
          <button class="sm danger" @click="rmEnv(settings.defaults.env,i)">✕</button></div>
        <button class="sm" @click="addEnv(settings.defaults.env)">+ env var</button>
        <div style="margin-top:12px"><button class="primary" @click="saveSettings">Save defaults</button> <span class="ok" v-if="settingsMsg">{{settingsMsg}}</span></div>
      </div>
      <div class="card"><h2>Change password</h2>
        <label>Current</label><input type="password" v-model="pw.current">
        <label>New</label><input type="password" v-model="pw.next">
        <div class="err" v-if="pw.err">{{pw.err}}</div><div class="ok" v-if="pw.msg">{{pw.msg}}</div>
        <div style="margin-top:12px"><button class="primary" @click="changePw">Update password</button></div>
      </div>
    </div>
  </div>
</div>

<!-- CHANGE PASSWORD (forced) -->
<div v-if="me && pw.show" class="modal-bg"><div class="modal">
  <h2 style="margin-top:0">Set a new password</h2>
  <div class="muted" style="font-size:12px">You're using the default password — change it to continue.</div>
  <label>Current</label><input type="password" v-model="pw.current">
  <label>New</label><input type="password" v-model="pw.next">
  <div class="err" v-if="pw.err">{{pw.err}}</div><div class="ok" v-if="pw.msg">{{pw.msg}}</div>
  <div class="right" style="margin-top:14px"><button class="primary" @click="changePw">Save</button></div>
</div></div>

<!-- REPO EDIT MODAL -->
<div v-if="repoForm" class="modal-bg"><div class="modal">
  <h2 style="margin-top:0">{{editing=='new'?'Add repository':'Edit repository'}}</h2>
  <label>Git URL</label><input v-model="repoForm.url" placeholder="https://github.com/OWNER/REPO">
  <div class="row"><div><label>Name</label><input v-model="repoForm.name"></div>
    <div><label>Schedule (cron, UTC)</label><input class="mono" v-model="repoForm.cron" placeholder="0 3 * * *"></div></div>
  <div class="muted" style="font-size:12px;margin-top:4px">{{cronText(repoForm.cron)}}</div>
  <label>Context — focus areas, what is NOT an issue, triage hints</label>
  <textarea v-model="repoForm.context" placeholder="Focus on auth/IDOR and file upload. The /health endpoint is public by design (not an issue). Ignore test fixtures."></textarea>
  <label class="flex" style="margin-top:10px"><input type="checkbox" style="width:auto" v-model="repoForm.enabled"> <span>Enabled (scheduled scanning)</span></label>
  <div class="muted" style="font-size:12px;margin-top:10px">The AI backend, model, keys and args are set once for all repositories in <a @click="editing=null;repoForm=null;go('settings')">Settings → AI configuration</a>.</div>
  <div class="err" v-if="formErr">{{formErr}}</div>
  <div class="right flex" style="margin-top:14px;justify-content:flex-end">
    <button @click="editing=null;repoForm=null">Cancel</button>
    <button class="primary" @click="saveRepo">Save</button></div>
</div></div>

<!-- SCAN LOG MODAL -->
<div v-if="scanView" class="modal-bg"><div class="modal" style="width:min(900px,96vw)">
  <div class="flex"><h2 style="margin:0">Scan #{{scanView.id}} · {{scanView.slug}}</h2><span class="spacer"></span>
    <span class="pill" :class="scanView.status"><span v-if="isLive(scanView)" class="dot pulse on"></span>{{scanView.status}}</span>
    <button class="sm" @click="relaunchScan(scanView)">Relaunch</button>
    <button class="sm danger" :disabled="isLive(scanView)" @click="deleteScan(scanView)">Delete</button>
    <button class="sm" @click="scanView=null">close</button></div>
  <div class="muted" style="font-size:12px;margin:6px 0">
    <span v-if="scanView.status==='running'" class="live">{{heartbeatText(scanView)}}</span>
    <span v-else>{{scanView.new_count}} new · {{scanView.mitigated_count}} mitigated · {{scanView.total_count}} open · {{money(scanView.cost_usd)}} spent · commit {{(scanView.commit_sha||'').slice(0,8)}}</span>
    <span v-if="scanView.error" class="err" style="margin-left:8px">{{scanView.error}}</span>
  </div>
  <div v-if="scanView.findings && scanView.findings.length">
    <h2 style="margin:14px 0 6px">Findings in this scan ({{scanView.findings.length}})</h2>
    <table><thead><tr><th>Sev</th><th>Title</th><th>Where</th><th>Status</th></tr></thead>
      <tbody><tr v-for="f in scanView.findings" :key="f.uuid||f.id" style="cursor:pointer" @click="openFindingFromScan(f)">
        <td><span class="badge" :class="'b-'+f.severity">{{f.severity}}</span></td>
        <td>{{f.title}}</td><td class="mono muted">{{f.file}}{{f.line?':'+f.line:''}}</td>
        <td><span class="pill" :class="f.status">{{f.status}}</span>
          <span v-if="f.triage && f.triage!=='unset'" class="tri" :class="'tri-'+f.triage">{{triageShort(f.triage)}}</span></td></tr></tbody></table>
  </div>
  <h2 style="margin:14px 0 6px">Log</h2>
  <pre class="log" ref="logEl">{{scanView.log||'(no output yet)'}}</pre>
</div></div>

<!-- AUTHORIZE TERMINAL MODAL (xterm.js <-> PTY) -->
<div v-if="authModal" class="modal-bg"><div class="modal" style="width:min(860px,96vw)">
  <div class="flex"><h2 style="margin:0">Authorize {{authModal}}</h2><span class="spacer"></span>
    <button class="sm" @click="closeAuth">close</button></div>
  <div class="muted" style="font-size:12px;margin:6px 0">Follow the login prompts below. If a URL or device code appears, open it in your own browser to complete sign-in. Credentials persist on the data volume, so you only do this once.</div>
  <div ref="termEl" style="height:60vh;background:#0d1117;border:1px solid var(--line);border-radius:8px;padding:6px;overflow:hidden"></div>
</div></div>
`,
}).mount('#app');

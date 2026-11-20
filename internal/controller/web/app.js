'use strict';
// mocat 控制台前端：原生 JS 单页应用，无构建步骤。
// CSP 不允许内联脚本，所有交互通过 data-action 事件委托处理。

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const S = { templates: [], nodes: [], refresh: null, route: '', chainDraft: null };

// ---------- 通用 ----------
async function api(method, path, body) {
  const opt = { method, headers: { 'X-Mocat': '1' }, credentials: 'same-origin' };
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const resp = await fetch(path, opt);
  let data = null;
  try { data = await resp.json(); } catch (e) { /* 非 JSON */ }
  if (resp.status === 401 && path !== '/api/login') { showLogin(); throw new Error('请先登录'); }
  if (!resp.ok) throw new Error((data && data.error) || ('请求失败：' + resp.status));
  return data;
}

function toast(msg, bad) {
  const t = $('#toast');
  t.textContent = msg; t.className = 'toast' + (bad ? ' bad' : '');
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.add('hidden'), bad ? 6000 : 2500);
}

function fmtBytes(n) {
  n = Number(n || 0);
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(n >= 100 ? 0 : n >= 10 ? 1 : 2) : n) + ' ' + u[i];
}
const fmtRate = n => fmtBytes(n) + '/s';
function fmtTime(sec) {
  if (!sec) return '-';
  const d = new Date(sec * 1000), p = x => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
function ago(sec) {
  if (!sec) return '从未';
  const s = Math.max(0, Math.floor(Date.now() / 1000 - sec));
  if (s < 60) return s + ' 秒前';
  if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
  if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
  return fmtTime(sec);
}

const STATE = { running: '运行中', failed: '失败', disabled: '已停用', syncing: '同步中', pending: '等待中', offline: '节点离线', online: '在线' };
const badge = (st, label) => `<span class="badge ${esc(st)}">${esc(label || STATE[st] || st)}</span>`;
const OBFS = { none: '不伪装', fakehttp: 'FakeHTTP', fakesip: 'FakeSIP' };
const BACKEND = { socat: 'socat', nft: 'nftables' };
const opts = (list, cur) => list.map(([v, l]) => `<option value="${esc(v)}"${String(v) === String(cur) ? ' selected' : ''}>${esc(l)}</option>`).join('');

function openModal(html) { $('#modal-body').innerHTML = html; $('#modal').classList.remove('hidden'); const f = $('#modal-body input, #modal-body select'); if (f) f.focus(); }
function closeModal() { $('#modal').classList.add('hidden'); $('#modal-body').innerHTML = ''; }
const formData = form => Object.fromEntries(new FormData(form).entries());
function formErr(form, msg) { const e = $('.err', form); if (e) e.textContent = msg; else toast(msg, true); }

async function loadTemplates() { S.templates = await api('GET', '/api/templates'); }
async function loadNodes() { S.nodes = await api('GET', '/api/nodes'); }

// ---------- 登录 ----------
function showLogin() { $('#app').classList.add('hidden'); $('#login').classList.remove('hidden'); closeModal(); stopRefresh(); }
async function boot() {
  try {
    const me = await api('GET', '/api/me');
    $('#user-name').textContent = me.user;
    $('#login').classList.add('hidden'); $('#app').classList.remove('hidden');
    await loadTemplates();
    route();
  } catch (e) { showLogin(); }
}
$('#login-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  const d = formData(ev.target);
  try {
    await api('POST', '/api/login', d);
    $('#login-err').textContent = ''; ev.target.password.value = '';
    boot();
  } catch (e) { $('#login-err').textContent = e.message; }
});

// ---------- 路由 ----------
function stopRefresh() { clearInterval(S.timer); S.refresh = null; }
function setRefresh(fn) {
  stopRefresh(); S.refresh = fn;
  S.timer = setInterval(() => { if ($('#modal').classList.contains('hidden') && S.refresh) S.refresh().catch(() => {}); }, 5000);
}
async function route() {
  const h = location.hash.replace(/^#/, '') || '/';
  const parts = h.split('/').filter(Boolean);
  const nav = parts[0] || 'overview';
  $$('#nav a').forEach(a => a.classList.toggle('active', a.dataset.nav === nav));
  stopRefresh();
  const main = $('#main');
  const page = {
    overview: pageOverview, nodes: parts[1] ? m => pageNode(m, decodeURIComponent(parts[1])) : pageNodes, rules: pageRules,
    chains: pageChains, templates: pageTemplates, audit: pageAudit, settings: pageSettings,
  }[nav] || pageOverview;
  try { await page(main); } catch (e) { main.innerHTML = `<div class="alert">${esc(e.message)}</div>`; }
}
window.addEventListener('hashchange', route);

// ---------- 总览（C-50） ----------
async function pageOverview(main) {
  const render = async () => {
    const o = await api('GET', '/api/overview');
    main.innerHTML = `<h2>总览</h2>
      <div class="grid">
        ${stat('节点总数', o.nodes)}${stat('在线节点', o.online, o.online < o.nodes)}
        ${stat('规则总数', o.rules)}${stat('异常规则', o.failed_rules, o.failed_rules > 0)}
        ${stat('转发链', o.chains)}${stat('异常转发链', o.failed_chains, o.failed_chains > 0)}
        ${stat('当前连接数', o.conns)}${stat('实时速率', '↑' + fmtRate(o.rate_up) + '<br>↓' + fmtRate(o.rate_down))}
        ${stat('累计上行', fmtBytes(o.up_bytes))}${stat('累计下行', fmtBytes(o.down_bytes))}
      </div>
      <div class="card"><h3>需要关注</h3>
        ${(o.problems || []).length ? `<div class="table-wrap"><table><tr><th>类型</th><th>对象</th><th>原因</th></tr>
          ${o.problems.map(p => `<tr><td>${badge('failed', p.Kind)}</td><td>${esc(p.Name)}</td><td class="small-text">${esc(p.Reason)}</td></tr>`).join('')}</table></div>`
        : '<div class="muted">一切正常</div>'}
      </div>`;
  };
  await render(); setRefresh(render);
}
const stat = (label, value, bad) => `<div class="stat"><div class="label">${esc(label)}</div><div class="value${bad ? ' bad' : ''}">${typeof value === 'number' ? value : value}</div></div>`;

// ---------- 节点列表（C-10/C-11/C-14） ----------
async function pageNodes(main) {
  const render = async () => {
    await loadNodes();
    main.innerHTML = `<h2>节点 <button class="btn primary" data-action="node-new">新建节点</button></h2>
      <div class="card table-wrap"><table>
        <tr><th>名称</th><th>管理地址</th><th>状态</th><th>最后连接</th><th>版本</th><th>架构</th><th>规则</th><th>累计 ↑/↓</th><th>速率 ↑/↓</th><th>连接</th></tr>
        ${S.nodes.map(n => {
          const st = n.runtime.status || {};
          return `<tr>
            <td><a href="#/nodes/${esc(n.id)}">${esc(n.name)}</a><div class="muted small-text">${esc(n.remark)}</div></td>
            <td><code>${esc(n.host)}:${n.port}</code></td>
            <td>${n.runtime.online ? badge('online') : badge('offline', '离线')}
                ${n.runtime.fp_alert ? badge('failed', '证书变化') : ''}
                ${n.runtime.online && !n.synced ? badge('syncing', '同步中') : ''}
                ${!n.runtime.online && n.runtime.last_error ? `<div class="reason">${esc(n.runtime.last_error)}</div>` : ''}</td>
            <td>${ago(n.runtime.last_seen)}</td>
            <td>${esc(st.version || '-')}</td>
            <td>${esc((st.system || {}).arch || '-')}</td>
            <td>${n.rule_count}${n.failed_rules ? ` <span class="badge failed">${n.failed_rules} 异常</span>` : ''}</td>
            <td>${fmtBytes(n.up_bytes)} / ${fmtBytes(n.down_bytes)}</td>
            <td>${fmtRate(n.rate_up)} / ${fmtRate(n.rate_down)}</td>
            <td>${n.conns}</td></tr>`;
        }).join('') || '<tr><td colspan="10" class="muted">还没有节点，点击「新建节点」添加</td></tr>'}
      </table></div>`;
  };
  await render(); setRefresh(render);
}

function nodeForm(n) {
  n = n || { port: 9443 };
  return `<form data-form="node-save" data-id="${esc(n.id || '')}">
    <h3>${n.id ? '编辑节点' : '新建节点'}</h3>
    <div class="row">
      <label>名称<input name="name" value="${esc(n.name)}" required maxlength="64"></label>
      <label>备注<input name="remark" value="${esc(n.remark)}"></label>
    </div>
    <div class="row">
      <label>管理地址（IP / 域名）<input name="host" value="${esc(n.host)}" required placeholder="203.0.113.10"></label>
      <label>管理端口<input name="port" type="number" min="1" max="65535" value="${esc(n.port)}" required></label>
    </div>
    <label>数据面地址（可选，作为链中上一跳的目标；为空时同管理地址）<input name="data_host" value="${esc(n.data_host)}"></label>
    <p class="muted small-text">控制端会主动连接节点的管理端口，请确保该端口可从控制端访问。</p>
    <div class="err"></div>
    <div class="modal-actions"><button type="button" class="btn" data-action="close">取消</button><button class="btn primary">保存</button></div>
  </form>`;
}

function installHTML(inst, title) {
  const pk = inst.packages || [];
  return `<h3>${esc(title || '安装 / 启动节点')}</h3>
    <p>在节点主机上以 root 执行以下命令（命令中包含节点凭据，请妥善保管）：</p>
    <label>一键安装（从控制端下载安装包，校验控制端证书公钥）</label>
    <pre>${esc(inst.one_click)}</pre><button class="btn small" data-action="copy" data-text="${esc(inst.one_click)}">复制</button>
    ${pk.length ? `<span class="muted small-text">控制端已提供安装包：${pk.map(esc).join('、')}</span>`
      : `<div class="alert warn" style="margin-top:8px">控制端数据目录下的 packages/ 中还没有节点安装包，一键安装暂不可用；请先把发行包放到该目录，或手动安装后使用下面的命令。</div>`}
    <label style="margin-top:12px">已手动解压发行包到 /opt/mocat 时</label>
    <pre>${esc(inst.manual)}</pre><button class="btn small" data-action="copy" data-text="${esc(inst.manual)}">复制</button>
    <div class="modal-actions"><button class="btn primary" data-action="close">完成</button></div>`;
}

// ---------- 节点详情（C-12） ----------
async function pageNode(main, id) {
  const render = async () => {
    const d = await api('GET', '/api/nodes/' + encodeURIComponent(id));
    const n = d.node, rt = n.runtime, st = rt.status;
    const sys = (st && st.system) || {};
    main.innerHTML = `<h2>${esc(n.name)} ${rt.online ? badge('online') : badge('offline', '离线')}
        <span>
        <button class="btn" data-action="node-edit" data-id="${esc(n.id)}">编辑</button>
        <button class="btn" data-action="node-install" data-id="${esc(n.id)}">安装命令</button>
        <button class="btn" data-action="node-sync" data-id="${esc(n.id)}">立即同步</button>
        <button class="btn" data-action="node-reset" data-id="${esc(n.id)}">重置凭据</button>
        <button class="btn danger" data-action="node-del" data-id="${esc(n.id)}" data-name="${esc(n.name)}">删除</button></span></h2>
      ${!rt.online ? `<div class="alert">节点离线：${esc(rt.last_error || '尚未连接')}（最后连接：${ago(rt.last_seen)}）</div>` : ''}
      ${rt.fp_alert ? `<div class="alert">节点证书指纹已变化，控制端已拒绝连接。新指纹：<code>${esc(rt.fp_alert)}</code>。如确认是节点重新生成了证书，可
         <button class="btn small" data-action="node-trust" data-id="${esc(n.id)}">信任新证书</button></div>` : ''}
      ${rt.sync_error ? `<div class="alert warn">${esc(rt.sync_error)}</div>` : ''}
      ${st && (st.warnings || []).length ? `<div class="alert warn">节点运行条件检查：<br>${st.warnings.map(esc).join('<br>')}</div>` : ''}
      <div class="grid">
        ${stat('规则', n.rule_count)}${stat('异常规则', n.failed_rules, n.failed_rules > 0)}${stat('当前连接', n.conns)}
        ${stat('实时速率', '↑' + fmtRate(n.rate_up) + '<br>↓' + fmtRate(n.rate_down))}${stat('累计', '↑' + fmtBytes(n.up_bytes) + '<br>↓' + fmtBytes(n.down_bytes))}
      </div>
      <div class="card"><h3>转发规则 <button class="btn small primary" data-action="rule-new" data-node="${esc(n.id)}">新建规则</button></h3>
        ${rulesTable(d.rules, false)}</div>
      <div class="card"><h3>流量趋势（最近 24 小时）</h3><div id="traffic-chart" class="muted">加载中…</div></div>
      <div class="row">
        <div class="card"><h3>节点信息</h3><div class="kv">
          <div>管理地址</div><div><code>${esc(n.host)}:${n.port}</code></div>
          <div>数据面地址</div><div>${esc(n.data_host || n.host)}</div>
          <div>备注</div><div>${esc(n.remark || '-')}</div>
          <div>节点版本</div><div>${esc(st ? st.version : '-')}</div>
          <div>主机名</div><div>${esc(sys.hostname || '-')}</div>
          <div>系统</div><div>${esc(sys.distro || sys.os || '-')}</div>
          <div>架构</div><div>${esc(sys.arch || '-')}</div>
          <div>内核</div><div>${esc(sys.kernel || '-')}</div>
          <div>节点启动时间</div><div>${st ? fmtTime(st.started_at) : '-'}</div>
          <div>最后连接</div><div>${ago(rt.last_seen)}</div>
          <div>配置版本</div><div>控制端 ${n.config_version} / 节点 ${st ? st.config_version : '-'} ${n.synced ? badge('running', '已同步') : badge('syncing', '未同步')}</div>
          <div>证书指纹</div><div class="small-text"><code>${esc(n.cert_fp || '尚未记录')}</code></div>
        </div></div>
        <div class="card"><h3>后端可用性</h3>
          ${st ? `<table><tr><th>组件</th><th>状态</th><th>说明</th></tr>${(st.backends || []).map(b => `<tr><td>${esc(b.name)}</td>
            <td>${b.available ? badge('running', '可用') : badge('failed', '不可用')}</td>
            <td class="small-text">${esc(b.version || '')} ${esc(b.path || '')}<div class="muted">${esc(b.note || '')}</div></td></tr>`).join('')}</table>` : '<div class="muted">节点离线</div>'}
        </div>
      </div>
      <div class="card"><h3>节点日志 <button class="btn small" data-action="node-logs" data-id="${esc(n.id)}">加载最近日志</button></h3><div id="node-logs"></div></div>`;
    loadChart(id);
  };
  await render();
  setRefresh(async () => { const logs = $('#node-logs') && $('#node-logs').innerHTML; await render(); if (logs) $('#node-logs').innerHTML = logs; });
}

async function loadChart(id) {
  const el = $('#traffic-chart');
  try {
    const pts = await api('GET', `/api/nodes/${encodeURIComponent(id)}/traffic?hours=24`);
    if (el) el.innerHTML = chartSVG(pts);
  } catch (e) { if (el) el.textContent = e.message; }
}

function chartSVG(pts) {
  if (!pts.length) return '<div class="muted">暂无数据（控制端每分钟记录一次）</div>';
  const W = 900, H = 200, L = 70, B = 22, T = 8;
  const t0 = pts[0].time, t1 = Math.max(pts[pts.length - 1].time, t0 + 60);
  const up = pts.map(p => p.up / 60), down = pts.map(p => p.down / 60);
  const max = Math.max(1, ...up, ...down);
  const x = t => L + (t - t0) / (t1 - t0) * (W - L - 10);
  const y = v => T + (1 - v / max) * (H - T - B);
  const line = (arr, color) => `<polyline fill="none" stroke="${color}" stroke-width="1.5" points="${pts.map((p, i) => x(p.time).toFixed(1) + ',' + y(arr[i]).toFixed(1)).join(' ')}"/>`;
  const tl = s => { const d = new Date(s * 1000); return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0'); };
  return `<div class="legend"><span><i style="background:#2f6fde"></i>上行</span><span><i style="background:#1f9d55"></i>下行</span></div>
    <svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
      <line x1="${L}" y1="${T}" x2="${L}" y2="${H - B}" stroke="currentColor" stroke-opacity=".2"/>
      <line x1="${L}" y1="${H - B}" x2="${W - 10}" y2="${H - B}" stroke="currentColor" stroke-opacity=".2"/>
      <text x="${L - 6}" y="${T + 10}" text-anchor="end">${esc(fmtRate(max))}</text>
      <text x="${L - 6}" y="${H - B}" text-anchor="end">0</text>
      <text x="${L}" y="${H - 6}">${tl(t0)}</text><text x="${W - 10}" y="${H - 6}" text-anchor="end">${tl(t1)}</text>
      ${line(up, '#2f6fde')}${line(down, '#1f9d55')}
    </svg>`;
}

// ---------- 规则（C-20） ----------
function obfsSummary(o, resolved) {
  if (!o || !o.type || o.type === 'none') return '<span class="muted">不伪装</span>';
  let s = OBFS[o.type] || o.type;
  if (o.template_id) { const t = S.templates.find(t => t.id === o.template_id); s += `<div class="muted small-text">模板：${esc(t ? t.name : o.template_id)}</div>`; }
  else if (resolved && resolved.obfs && resolved.obfs.params) {
    const p = resolved.obfs.params; s += `<div class="muted small-text">${esc(p.host || p.uri || '')} TTL=${esc(p.ttl || '')}</div>`;
  }
  return s;
}

function rulesTable(rules, showNode) {
  if (!rules.length) return '<div class="muted">暂无规则</div>';
  return `<div class="table-wrap"><table>
    <tr><th>名称</th>${showNode ? '<th>节点</th>' : ''}<th>协议</th><th>监听</th><th>目标</th><th>后端</th><th>伪装</th><th>状态</th><th>累计 ↑/↓</th><th>速率 ↑/↓</th><th>连接</th><th>操作</th></tr>
    ${rules.map(r => `<tr>
      <td>${esc(r.name)}${r.source === 'chain' ? `<div class="small-text"><a href="#/chains">转发链第 ${r.hop + 1} 跳</a></div>` : ''}
          ${r.remark ? `<div class="muted small-text">${esc(r.remark)}</div>` : ''}</td>
      ${showNode ? `<td><a href="#/nodes/${esc(r.node_id)}">${esc(r.node_name)}</a></td>` : ''}
      <td>${esc((r.protocol || '').toUpperCase())}</td>
      <td><code>${esc(r.listen_addr || '*')}:${r.listen_port}</code></td>
      <td><code>${esc(r.target_host)}:${r.target_port}</code>${r.resolved_ip && r.resolved_ip !== r.target_host ? `<div class="muted small-text">${esc(r.resolved_ip)}</div>` : ''}</td>
      <td>${esc(BACKEND[r.backend] || r.backend)}</td>
      <td>${obfsSummary(r.obfs, r.resolved)}</td>
      <td>${badge(r.state)}${r.reason ? `<div class="reason">${esc(r.reason)}</div>` : ''}${r.stats && r.stats.blocked ? `<div class="reason">伪装队列丢弃 ${r.stats.blocked} 个报文</div>` : ''}</td>
      <td class="small-text">${fmtBytes(r.stats.up_bytes)}<br>${fmtBytes(r.stats.down_bytes)}</td>
      <td class="small-text">${fmtRate(r.rate.up)}<br>${fmtRate(r.rate.down)}</td>
      <td>${r.stats.conns || 0}</td>
      <td style="white-space:nowrap">${r.source === 'rule' ? `
        <button class="btn small" data-action="rule-edit" data-id="${esc(r.id)}">编辑</button>
        <button class="btn small" data-action="rule-toggle" data-id="${esc(r.id)}">${r.enabled ? '停用' : '启用'}</button>
        <button class="btn small danger" data-action="rule-del" data-id="${esc(r.id)}" data-name="${esc(r.name)}">删除</button>` : '<span class="muted small-text">在转发链中编辑</span>'}</td>
    </tr>`).join('')}</table></div>`;
}

async function pageRules(main) {
  const render = async () => {
    const rules = await api('GET', '/api/rules');
    rules.sort((a, b) => (a.node_name + a.name).localeCompare(b.node_name + b.name));
    main.innerHTML = `<h2>规则 <button class="btn primary" data-action="rule-new">新建规则</button></h2>
      <div class="card">${rulesTable(rules, true)}</div>`;
  };
  await render(); setRefresh(render);
}

// 伪装编辑器：按协议给出可选伪装方式；可以引用模板或填写自定义参数（C-22、C-30）
function obfsHTML(proto, o) {
  o = o || { type: 'none' };
  const types = proto === 'udp' ? [['none', '不伪装'], ['fakesip', 'FakeSIP（模拟 SIP）']] : [['none', '不伪装'], ['fakehttp', 'FakeHTTP（模拟 HTTP）']];
  const type = types.some(t => t[0] === o.type) ? o.type : 'none';
  let h = `<label>伪装方式（作用于本节点出站方向）<select data-role="obfs-type">${opts(types, type)}</select></label>`;
  if (type !== 'none') {
    const tpls = S.templates.filter(t => t.type === type);
    let tplId = o.template_id;
    if (tplId === undefined || tplId === null) tplId = o.params ? '' : (tpls[0] ? tpls[0].id : '');
    h += `<label>参数<select data-role="obfs-tpl">${opts(tpls.map(t => [t.id, '模板：' + t.name]), tplId)}<option value=""${tplId === '' ? ' selected' : ''}>自定义参数</option></select></label>`;
    if (tplId === '') {
      const p = Object.assign(defaultParams(type), o.params || {});
      h += paramFields(type, p);
    } else {
      const t = tpls.find(t => t.id === tplId);
      if (t) h += `<div class="muted small-text">${esc(t.params.host || t.params.uri)}，TTL ${t.params.ttl}，重复 ${t.params.repeat} 次${t.params.payload_b64 ? '，自定义载荷' : ''}</div>`;
    }
  }
  return h;
}
const defaultParams = type => type === 'fakesip' ? { uri: 'sip:10086@sip.example.com', ttl: 3, repeat: 2 } : { host: 'www.speedtest.net', ttl: 3, repeat: 2 };
function paramFields(type, p) {
  return `<div class="row">
    ${type === 'fakehttp' ? `<label>HTTP Host<input data-role="obfs-host" value="${esc(p.host)}"></label>` : `<label>SIP URI<input data-role="obfs-uri" value="${esc(p.uri)}"></label>`}
    <label>TTL（伪装报文在到达对端前过期）<input data-role="obfs-ttl" type="number" min="1" max="255" value="${esc(p.ttl)}"></label>
    <label>重复次数<input data-role="obfs-repeat" type="number" min="1" max="10" value="${esc(p.repeat)}"></label>
  </div>
  <label>自定义载荷（可选，base64，最大 1400 字节；填写后替代 Host/URI）<textarea data-role="obfs-payload" rows="2">${esc(p.payload_b64 || '')}</textarea></label>`;
}
function readObfs(box) {
  const type = $('[data-role=obfs-type]', box).value;
  if (type === 'none') return { type };
  const tplSel = $('[data-role=obfs-tpl]', box);
  const tpl = tplSel ? tplSel.value : undefined;
  if (tpl) return { type, template_id: tpl };
  if (tpl === undefined) return { type };
  const v = r => { const e = $(`[data-role=${r}]`, box); return e ? e.value.trim() : ''; };
  if (!$('[data-role=obfs-ttl]', box)) return { type, template_id: '', params: null };
  const p = { ttl: +v('obfs-ttl'), repeat: +v('obfs-repeat') };
  if (type === 'fakehttp') p.host = v('obfs-host'); else p.uri = v('obfs-uri');
  if (v('obfs-payload')) p.payload_b64 = v('obfs-payload');
  return { type, template_id: '', params: p };
}
function rerenderObfs(box, proto) {
  const o = readObfs(box);
  box.innerHTML = obfsHTML(proto, o);
}

function ruleForm(r, nodeFixed) {
  r = r || { enabled: true, protocol: 'tcp', backend: 'socat', obfs: { type: 'none' } };
  return `<form data-form="rule-save" data-id="${esc(r.id || '')}">
    <h3>${r.id ? '编辑规则' : '新建规则'}</h3>
    <div class="row">
      <label>节点<select name="node_id" ${r.id || nodeFixed ? 'disabled' : ''}>${opts(S.nodes.map(n => [n.id, n.name]), r.node_id || nodeFixed)}</select></label>
      <label>名称<input name="name" value="${esc(r.name)}" placeholder="可留空自动生成"></label>
      <label>备注<input name="remark" value="${esc(r.remark)}"></label>
    </div>
    <div class="row">
      <label>协议<select name="protocol" data-role="proto">${opts([['tcp', 'TCP'], ['udp', 'UDP']], r.protocol)}</select></label>
      <label>转发后端<select name="backend">${opts([['socat', 'socat（用户态）'], ['nft', 'nftables DNAT（内核态）']], r.backend)}</select></label>
      <label>&nbsp;<span><input type="checkbox" name="enabled" ${r.enabled ? 'checked' : ''}>启用</span></label>
    </div>
    <div class="row">
      <label>监听地址（可选，默认所有 IPv4 地址）<input name="listen_addr" value="${esc(r.listen_addr)}" placeholder="0.0.0.0"></label>
      <label>监听端口<input name="listen_port" type="number" min="1" max="65535" value="${esc(r.listen_port)}" required></label>
    </div>
    <div class="row">
      <label>目标地址（IPv4 / IPv6 / 域名）<input name="target_host" value="${esc(r.target_host)}" required></label>
      <label>目标端口<input name="target_port" type="number" min="1" max="65535" value="${esc(r.target_port)}" required></label>
    </div>
    <div class="obfs-box" data-role="obfs">${obfsHTML(r.protocol, r.obfs)}</div>
    <div class="err"></div>
    <div class="modal-actions"><button type="button" class="btn" data-action="close">取消</button><button class="btn primary">保存</button></div>
  </form>`;
}

async function saveRuleForm(form) {
  const d = formData(form);
  const id = form.dataset.id;
  const nodeSel = $('[name=node_id]', form);
  const body = {
    node_id: nodeSel.value, name: d.name, remark: d.remark, enabled: !!$('[name=enabled]', form).checked,
    protocol: d.protocol, backend: d.backend, listen_addr: d.listen_addr, listen_port: +d.listen_port,
    target_host: d.target_host, target_port: +d.target_port, obfs: readObfs($('[data-role=obfs]', form)),
  };
  if (id) await api('PUT', '/api/rules/' + encodeURIComponent(id), body); else await api('POST', '/api/rules', body);
}

// ---------- 转发链（C-21 ~ C-25） ----------
async function pageChains(main) {
  const render = async () => {
    const chains = await api('GET', '/api/chains');
    main.innerHTML = `<h2>转发链 <button class="btn primary" data-action="chain-new">新建转发链</button></h2>
      ${chains.map(c => `<div class="card">
        <h3>${esc(c.name)} ${badge(c.state)} <span class="muted small-text">${esc(c.protocol.toUpperCase())}</span>
          <span style="margin-left:auto">
            <button class="btn small" data-action="chain-edit" data-id="${esc(c.id)}">编辑</button>
            <button class="btn small" data-action="chain-toggle" data-id="${esc(c.id)}">${c.enabled ? '停用' : '启用'}</button>
            <button class="btn small danger" data-action="chain-del" data-id="${esc(c.id)}" data-name="${esc(c.name)}">删除</button></span></h3>
        ${c.remark ? `<div class="muted small-text">${esc(c.remark)}</div>` : ''}
        <div class="chain-path">
          <span class="hopbox">用户</span><span class="arrow">→</span>
          ${c.hop_views.map(h => `<span class="hopbox">${esc(h.node_name)} <code>:${h.listen_port}</code> ${badge(h.state)}
             <div class="muted">${esc(BACKEND[h.backend] || h.backend)} · 出站${esc(OBFS[h.obfs.type] || '不伪装')}</div>
             ${h.reason ? `<div class="reason">${esc(h.reason)}</div>` : ''}${h.blocked ? `<div class="reason">伪装队列丢弃 ${h.blocked}</div>` : ''}</span><span class="arrow">→</span>`).join('')}
          <span class="hopbox">目标 <code>${esc(c.target_host)}:${c.target_port}</code></span>
        </div>
        <div class="muted small-text" style="margin-top:8px">入口：<code>${esc(c.entry)}</code> · 入口节点累计 ↑${fmtBytes(c.up_bytes)} ↓${fmtBytes(c.down_bytes)} · 速率 ↑${fmtRate(c.rate.up)} ↓${fmtRate(c.rate.down)} · 连接 ${c.conns}</div>
      </div>`).join('') || '<div class="card muted">还没有转发链。转发链会按顺序为每个节点自动生成规则：节点 A → 节点 B → … → 目标。</div>'}`;
  };
  await render(); setRefresh(render);
}

function chainForm(c) {
  S.chainDraft = JSON.parse(JSON.stringify(c || { enabled: true, protocol: 'tcp', hops: [] }));
  if (!S.chainDraft.hops.length) S.chainDraft.hops.push(newHop());
  return `<form data-form="chain-save" data-id="${esc(S.chainDraft.id || '')}">
    <h3>${S.chainDraft.id ? '编辑转发链' : '新建转发链'}</h3>
    <div class="row">
      <label>名称<input name="name" value="${esc(S.chainDraft.name)}" required></label>
      <label>备注<input name="remark" value="${esc(S.chainDraft.remark)}"></label>
      <label>协议（全程一致）<select name="protocol" data-role="proto">${opts([['tcp', 'TCP'], ['udp', 'UDP']], S.chainDraft.protocol)}</select></label>
      <label>&nbsp;<span><input type="checkbox" name="enabled" ${S.chainDraft.enabled ? 'checked' : ''}>启用</span></label>
    </div>
    <div id="hops"></div>
    <button type="button" class="btn" data-action="hop-add">＋ 添加节点</button>
    <div class="row" style="margin-top:12px">
      <label>最终目标地址<input name="target_host" value="${esc(S.chainDraft.target_host)}" required></label>
      <label>最终目标端口<input name="target_port" type="number" min="1" max="65535" value="${esc(S.chainDraft.target_port)}" required></label>
    </div>
    <p class="muted small-text">用户 → 第 1 个节点这一段不伪装；每个节点的伪装作用于它发往下一跳（或最终目标）的出站连接。中转端口填 0 表示自动分配。</p>
    <div class="err"></div>
    <div class="modal-actions"><button type="button" class="btn" data-action="close">取消</button><button class="btn primary">保存</button></div>
  </form>`;
}
const newHop = () => ({ node_id: S.nodes[0] ? S.nodes[0].id : '', listen_port: 0, backend: 'socat', obfs: { type: 'none' } });

function renderHops() {
  const proto = $('[data-form=chain-save] [name=protocol]').value;
  const hops = S.chainDraft.hops;
  $('#hops').innerHTML = hops.map((h, i) => `<div class="hop" data-hop="${i}">
    <div class="hop-head"><span>第 ${i + 1} 跳${i === 0 ? '（入口节点）' : ''}</span><span>
      <button type="button" class="btn small" data-action="hop-up" data-i="${i}" ${i === 0 ? 'disabled' : ''}>上移</button>
      <button type="button" class="btn small" data-action="hop-down" data-i="${i}" ${i === hops.length - 1 ? 'disabled' : ''}>下移</button>
      <button type="button" class="btn small danger" data-action="hop-del" data-i="${i}" ${hops.length === 1 ? 'disabled' : ''}>移除</button></span></div>
    <div class="row">
      <label>节点<select data-role="hop-node">${opts(S.nodes.map(n => [n.id, n.name]), h.node_id)}</select></label>
      <label>${i === 0 ? '入口端口' : '中转端口'}（0 = 自动）<input data-role="hop-port" type="number" min="0" max="65535" value="${esc(h.listen_port)}"></label>
      <label>转发后端<select data-role="hop-backend">${opts([['socat', 'socat'], ['nft', 'nftables DNAT']], h.backend)}</select></label>
    </div>
    <div class="obfs-box" data-role="obfs">${obfsHTML(proto, h.obfs)}</div>
  </div>`).join('');
}
function syncDraft() {
  const f = $('[data-form=chain-save]');
  if (!f) return;
  $$('.hop', f).forEach(el => {
    const h = S.chainDraft.hops[+el.dataset.hop];
    h.node_id = $('[data-role=hop-node]', el).value;
    h.listen_port = +$('[data-role=hop-port]', el).value || 0;
    h.backend = $('[data-role=hop-backend]', el).value;
    h.obfs = readObfs($('[data-role=obfs]', el));
  });
}

// ---------- 伪装模板（C-30 / C-31） ----------
async function pageTemplates(main) {
  await loadTemplates();
  main.innerHTML = `<h2>伪装模板 <button class="btn primary" data-action="tpl-new">新建模板</button></h2>
    <div class="card table-wrap"><table><tr><th>名称</th><th>类型</th><th>Host / SIP URI</th><th>TTL</th><th>重复</th><th>自定义载荷</th><th>操作</th></tr>
    ${S.templates.map(t => `<tr><td>${esc(t.name)} ${t.builtin ? '<span class="badge">内置</span>' : ''}</td><td>${esc(OBFS[t.type])}</td>
      <td><code>${esc(t.params.host || t.params.uri)}</code></td><td>${t.params.ttl}</td><td>${t.params.repeat}</td><td>${t.params.payload_b64 ? '是' : '否'}</td>
      <td>${t.builtin ? '<span class="muted small-text">只读</span>' : `<button class="btn small" data-action="tpl-edit" data-id="${esc(t.id)}">编辑</button>
        <button class="btn small danger" data-action="tpl-del" data-id="${esc(t.id)}" data-name="${esc(t.name)}">删除</button>`}</td></tr>`).join('')}
    </table></div>
    <p class="muted small-text">修改模板后，引用该模板的规则会自动重新下发到相关节点。</p>`;
}
function tplForm(t) {
  t = t || { type: 'fakehttp', params: defaultParams('fakehttp') };
  return `<form data-form="tpl-save" data-id="${esc(t.id || '')}">
    <h3>${t.id ? '编辑模板' : '新建模板'}</h3>
    <div class="row">
      <label>名称<input name="name" value="${esc(t.name)}" required></label>
      <label>类型<select name="type" data-role="tpl-type" ${t.id ? 'disabled' : ''}>${opts([['fakehttp', 'FakeHTTP'], ['fakesip', 'FakeSIP']], t.type)}</select></label>
    </div>
    <div data-role="tpl-params">${paramFields(t.type, t.params)}</div>
    <div class="err"></div>
    <div class="modal-actions"><button type="button" class="btn" data-action="close">取消</button><button class="btn primary">保存</button></div>
  </form>`;
}

// ---------- 审计 / 账号 ----------
async function pageAudit(main) {
  const l = await api('GET', '/api/audit');
  main.innerHTML = `<h2>审计日志</h2><div class="card table-wrap"><table><tr><th>时间</th><th>用户</th><th>来源 IP</th><th>操作</th><th>详情</th></tr>
    ${l.map(e => `<tr><td style="white-space:nowrap">${fmtTime(e.time)}</td><td>${esc(e.user)}</td><td>${esc(e.ip)}</td><td>${esc(e.action)}</td>
      <td class="small-text" style="word-break:break-all">${esc(e.detail.length > 300 ? e.detail.slice(0, 300) + '…' : e.detail)}</td></tr>`).join('') || '<tr><td colspan="5" class="muted">暂无记录</td></tr>'}
    </table></div>`;
}
async function pageSettings(main) {
  main.innerHTML = `<h2>账号</h2><div class="card" style="max-width:420px"><form data-form="password">
    <h3>修改密码</h3>
    <label>原密码<input type="password" name="old" required autocomplete="current-password"></label>
    <label>新密码（至少 8 位）<input type="password" name="new" required minlength="8" autocomplete="new-password"></label>
    <label>确认新密码<input type="password" name="new2" required minlength="8" autocomplete="new-password"></label>
    <div class="err"></div><button class="btn primary">保存</button></form></div>`;
}

// ---------- 事件处理 ----------
const actions = {
  close: closeModal,
  async logout() { try { await api('POST', '/api/logout'); } catch (e) { /* ignore */ } showLogin(); },
  async copy(el) { try { await navigator.clipboard.writeText(el.dataset.text); toast('已复制'); } catch (e) { toast('复制失败，请手动选择复制', true); } },

  'node-new': () => openModal(nodeForm()),
  async 'node-edit'(el) { const d = await api('GET', '/api/nodes/' + el.dataset.id); openModal(nodeForm(d.node)); },
  async 'node-install'(el) { openModal(installHTML(await api('GET', `/api/nodes/${el.dataset.id}/install`))); },
  async 'node-sync'(el) { await api('POST', `/api/nodes/${el.dataset.id}/sync`); toast('已触发同步'); setTimeout(route, 1500); },
  async 'node-reset'(el) {
    if (!confirm('重置后旧凭据立即失效。节点在线时会自动推送新凭据，否则需要在节点上重新执行安装命令。确定重置？')) return;
    const r = await api('POST', `/api/nodes/${el.dataset.id}/reset-token`);
    openModal((r.pushed ? '<div class="alert warn">新凭据已推送到节点并生效。</div>' : '<div class="alert">节点当前不可达，新凭据未能推送。请在节点上执行下面的命令更新凭据。</div>') + installHTML(r.install, '新的节点凭据'));
  },
  async 'node-trust'(el) { if (!confirm('确认信任节点的新证书？')) return; await api('POST', `/api/nodes/${el.dataset.id}/trust-cert`); toast('已重置证书指纹，下次连接时记录新指纹'); setTimeout(route, 1500); },
  async 'node-del'(el) {
    if (!confirm(`确定删除节点「${el.dataset.name}」？其上的单节点规则会一并删除，节点在线时会先清空其转发规则。`)) return;
    await api('DELETE', '/api/nodes/' + el.dataset.id); toast('已删除'); location.hash = '#/nodes';
  },
  async 'node-logs'(el) {
    const box = $('#node-logs'); box.innerHTML = '<span class="muted">加载中…</span>';
    try {
      const logs = await api('GET', `/api/nodes/${el.dataset.id}/logs?n=300`);
      box.innerHTML = `<pre class="logs">${logs.map(l => esc(`${fmtTime(Math.floor(l.time / 1000))} ${l.level} ${l.msg}`)).join('\n') || '无日志'}</pre>`;
      const p = $('.logs', box); p.scrollTop = p.scrollHeight;
    } catch (e) { box.innerHTML = `<div class="alert">${esc(e.message)}</div>`; }
  },

  async 'rule-new'(el) { await loadNodes(); if (!S.nodes.length) return toast('请先新建节点', true); openModal(ruleForm(null, el.dataset.node)); },
  async 'rule-edit'(el) {
    await loadNodes();
    const rules = await api('GET', '/api/rules');
    const r = rules.find(x => x.id === el.dataset.id);
    if (r) openModal(ruleForm(r));
  },
  async 'rule-toggle'(el) {
    const rules = await api('GET', '/api/rules');
    const r = rules.find(x => x.id === el.dataset.id);
    if (!r) return;
    const body = { node_id: r.node_id, name: r.name, remark: r.remark, enabled: !r.enabled, protocol: r.protocol, backend: r.backend,
      listen_addr: r.listen_addr, listen_port: r.listen_port, target_host: r.target_host, target_port: r.target_port, obfs: r.obfs };
    await api('PUT', '/api/rules/' + r.id, body); toast(r.enabled ? '已停用' : '已启用'); route();
  },
  async 'rule-del'(el) { if (!confirm(`确定删除规则「${el.dataset.name}」？`)) return; await api('DELETE', '/api/rules/' + el.dataset.id); toast('已删除'); route(); },

  async 'chain-new'() { await loadNodes(); if (!S.nodes.length) return toast('请先新建节点', true); openModal(chainForm()); renderHops(); },
  async 'chain-edit'(el) {
    await loadNodes();
    const cs = await api('GET', '/api/chains');
    const c = cs.find(x => x.id === el.dataset.id);
    if (!c) return;
    openModal(chainForm({ id: c.id, name: c.name, remark: c.remark, enabled: c.enabled, protocol: c.protocol, target_host: c.target_host, target_port: c.target_port, hops: c.hops }));
    renderHops();
  },
  async 'chain-toggle'(el) {
    const cs = await api('GET', '/api/chains');
    const c = cs.find(x => x.id === el.dataset.id);
    if (!c) return;
    await api('PUT', '/api/chains/' + c.id, { name: c.name, remark: c.remark, enabled: !c.enabled, protocol: c.protocol, target_host: c.target_host, target_port: c.target_port, hops: c.hops });
    toast(c.enabled ? '已停用' : '已启用'); route();
  },
  async 'chain-del'(el) { if (!confirm(`确定删除转发链「${el.dataset.name}」？各节点上对应的规则会被移除。`)) return; await api('DELETE', '/api/chains/' + el.dataset.id); toast('已删除'); route(); },
  'hop-add'() { syncDraft(); S.chainDraft.hops.push(newHop()); renderHops(); },
  'hop-del'(el) { syncDraft(); S.chainDraft.hops.splice(+el.dataset.i, 1); renderHops(); },
  'hop-up'(el) { syncDraft(); const i = +el.dataset.i, h = S.chainDraft.hops; [h[i - 1], h[i]] = [h[i], h[i - 1]]; renderHops(); },
  'hop-down'(el) { syncDraft(); const i = +el.dataset.i, h = S.chainDraft.hops; [h[i + 1], h[i]] = [h[i], h[i + 1]]; renderHops(); },

  'tpl-new': () => openModal(tplForm()),
  'tpl-edit'(el) { const t = S.templates.find(x => x.id === el.dataset.id); if (t) openModal(tplForm(t)); },
  async 'tpl-del'(el) { if (!confirm(`确定删除模板「${el.dataset.name}」？`)) return; await api('DELETE', '/api/templates/' + el.dataset.id); toast('已删除'); route(); },
};

document.addEventListener('click', async ev => {
  const el = ev.target.closest('[data-action]');
  if (!el) { if (ev.target.id === 'modal') closeModal(); return; }
  const fn = actions[el.dataset.action];
  if (!fn) return;
  ev.preventDefault();
  try { await fn(el); } catch (e) { toast(e.message, true); }
});

document.addEventListener('change', ev => {
  const t = ev.target, role = t.dataset.role;
  if (role === 'obfs-type' || role === 'obfs-tpl') {
    const box = t.closest('[data-role=obfs]');
    const form = t.closest('form');
    rerenderObfs(box, $('[data-role=proto]', form).value);
  } else if (role === 'proto') {
    const form = t.closest('form');
    if (form.dataset.form === 'chain-save') { syncDraft(); renderHops(); }
    else $$('[data-role=obfs]', form).forEach(b => rerenderObfs(b, t.value));
  } else if (role === 'tpl-type') {
    $('[data-role=tpl-params]', t.closest('form')).innerHTML = paramFields(t.value, defaultParams(t.value));
  }
});

const forms = {
  async 'node-save'(form) {
    const d = formData(form); d.port = +d.port;
    const id = form.dataset.id;
    if (id) { await api('PUT', '/api/nodes/' + id, d); closeModal(); toast('已保存'); route(); return; }
    const r = await api('POST', '/api/nodes', d);
    openModal(installHTML(r.install, `节点「${r.node.name}」已创建`));
    route();
  },
  async 'rule-save'(form) { await saveRuleForm(form); closeModal(); toast('已保存，正在下发到节点'); route(); },
  async 'chain-save'(form) {
    syncDraft();
    const d = formData(form);
    const body = { name: d.name, remark: d.remark, enabled: !!$('[name=enabled]', form).checked, protocol: d.protocol,
      target_host: d.target_host, target_port: +d.target_port, hops: S.chainDraft.hops };
    const id = form.dataset.id;
    if (id) await api('PUT', '/api/chains/' + id, body); else await api('POST', '/api/chains', body);
    closeModal(); toast('已保存，正在下发到相关节点'); route();
  },
  async 'tpl-save'(form) {
    const id = form.dataset.id;
    const type = $('[name=type]', form).value;
    const box = $('[data-role=tpl-params]', form);
    const v = r => { const e = $(`[data-role=${r}]`, box); return e ? e.value.trim() : ''; };
    const params = { ttl: +v('obfs-ttl'), repeat: +v('obfs-repeat') };
    if (type === 'fakehttp') params.host = v('obfs-host'); else params.uri = v('obfs-uri');
    if (v('obfs-payload')) params.payload_b64 = v('obfs-payload');
    const body = { name: $('[name=name]', form).value, type, params };
    if (id) await api('PUT', '/api/templates/' + id, body); else await api('POST', '/api/templates', body);
    await loadTemplates(); closeModal(); toast('已保存'); route();
  },
  async password(form) {
    const d = formData(form);
    if (d.new !== d.new2) return formErr(form, '两次输入的新密码不一致');
    await api('POST', '/api/password', { old: d.old, new: d.new });
    form.reset(); formErr(form, ''); toast('密码已修改');
  },
};

document.addEventListener('submit', async ev => {
  const form = ev.target.closest('[data-form]');
  if (!form) return;
  ev.preventDefault();
  const fn = forms[form.dataset.form];
  if (!fn) return;
  const btn = $('button:not([type=button])', form);
  if (btn) btn.disabled = true;
  try { formErr(form, ''); await fn(form); } catch (e) { formErr(form, e.message); } finally { if (btn) btn.disabled = false; }
});

document.addEventListener('keydown', ev => { if (ev.key === 'Escape' && !$('#modal').classList.contains('hidden')) closeModal(); });

boot();

/* core.js — Tab 切换、初始化、toast 兼容、通用工具 */

function showToast(msg, ms) { toast(msg, ms); }

function switchTab(name) {
  document.querySelectorAll('.tab-btn').forEach(b => {
    const active = b.dataset.tab === name;
    b.classList.toggle('active', active);
    b.setAttribute('aria-selected', active ? 'true' : 'false');
    b.setAttribute('tabindex', active ? '0' : '-1');
  });
  document.querySelectorAll('.tab-panel').forEach(p => {
    const active = p.dataset.tab === name;
    p.classList.toggle('active', active);
    p.id = 'tab-panel-' + p.dataset.tab;
    p.setAttribute('role', 'tabpanel');
    p.setAttribute('aria-labelledby', 'tab-btn-' + p.dataset.tab);
    p.setAttribute('aria-hidden', active ? 'false' : 'true');
  });
  const sel = document.getElementById('tab-select');
  if (sel) sel.value = name;
  location.hash = name;
  if (name === 'aws') loadAwsConfig();
  if (name === 'ops') loadOpsConfig();
  if (name === 'diary') loadDiary(1);
  if (name === 'logs') loadLogs(1);
  if (name === 'abuse') loadSubStats(1);
  if (name === 'users') loadUsers(1);
  if (name === 'traffic') { loadTraffic(1); loadTrafficChart(); }
  if (name === 'backup') loadBackups();
}

// Tab 滚动渐隐提示
(function () {
  const bar = document.querySelector('.tab-bar');
  const fade = document.querySelector('.tab-fade-right');
  if (!bar || !fade) return;

  function checkFade() {
    fade.style.opacity = (bar.scrollLeft + bar.clientWidth >= bar.scrollWidth - 10) ? '0' : '1';
  }
  bar.addEventListener('scroll', checkFade);
  checkFade();

  const origSwitch = window.switchTab;
  window.switchTab = function (name) {
    origSwitch(name);
    const btn = bar.querySelector('[data-tab="' + name + '"]');
    if (btn) btn.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
    setTimeout(checkFade, 300);
  };
})();

// URL msg 参数提示
(function () {
  const _msg = new URLSearchParams(location.search).get('msg');
  if (_msg) {
    const m = { deploying: '🚀 部署中，请稍后刷新查看', added: '✅ 节点已添加', dup: '⚠️ IP 已存在' };
    if (m[_msg]) showToast(m[_msg]);
    history.replaceState(null, '', location.pathname + location.hash);
  }
})();

function toggleEdit(id) {
  // 兼容旧按钮：统一改为弹窗编辑
  if (typeof openNodeEditModal === 'function') {
    openNodeEditModal(id);
  }
}

function updateNodeLevel(id, level) {
  fetch('/admin/api/nodes/' + id + '/update-level', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ level })
  }).then(r => r.json()).then(d => { if (d.ok) showToast('等级已更新，节点配置同步中'); });
}




// 键盘左右切换 tab（可访问性）
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('keydown', (e) => {
    if (!['ArrowLeft','ArrowRight','Home','End'].includes(e.key)) return;
    const tabs = Array.from(document.querySelectorAll('.tab-btn'));
    const idx = tabs.indexOf(btn);
    let next = idx;
    if (e.key === 'ArrowRight') next = (idx + 1) % tabs.length;
    if (e.key === 'ArrowLeft') next = (idx - 1 + tabs.length) % tabs.length;
    if (e.key === 'Home') next = 0;
    if (e.key === 'End') next = tabs.length - 1;
    e.preventDefault();
    tabs[next].focus();
    switchTab(tabs[next].dataset.tab);
  });
});

// 初始 hash tab
if (location.hash.slice(1)) switchTab(location.hash.slice(1));

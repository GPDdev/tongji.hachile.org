const $ = (id) => document.getElementById(id);
const result = $('result');
let api = '';
let proofTimer;
function message(text, error = false) {
  result.textContent = text;
  result.classList.toggle('error', error);
}
function clearProof() {
  clearTimeout(proofTimer);
  $('proof-code').textContent = '';
  $('proof-panel').hidden = true;
}

// 回调码只留在本页内存，并立即从浏览器地址栏移除。
const callback = new URLSearchParams(location.hash.slice(1));
if (callback.has('proof') || callback.has('error')) {
  history.replaceState(null, '', location.pathname + location.search + '#identity');
  const proof = callback.get('proof');
  const expires = Number(callback.get('expires'));
  if (/^TJ-[A-Za-z0-9_-]{22}$/.test(proof || '') && expires > Date.now() / 1000 && expires <= Date.now() / 1000 + 610) {
    $('proof-code').textContent = proof;
    $('proof-expiry').textContent = `有效至 ${new Date(expires * 1000).toLocaleTimeString('zh-CN')}，或首次核验后失效。`;
    $('proof-panel').hidden = false;
    proofTimer = setTimeout(() => { clearProof(); message('证明码已过期，请重新认证。'); }, expires * 1000 - Date.now());
  } else {
    const errors = { denied: '你取消了学校授权，可以稍后重试。', expired: '认证会话已过期或不匹配，请重新开始。', failed: '认证未完成，请重试或联系站点维护者。', disabled: '账号认证尚未开放。' };
    message(errors[callback.get('error')] || '未收到有效的认证结果，请重新开始。', true);
  }
}

async function configure() {
  if (!window.TONGJI_API_ORIGIN) return;
  try {
    const url = new URL(window.TONGJI_API_ORIGIN);
    if (url.origin !== 'https://tongji-api.hachile.org') throw new Error('配置的接口地址不正确。');
    const response = await fetch(url.origin + '/api/config', { cache: 'no-store', signal: AbortSignal.timeout(10000) });
    if (!response.ok) throw new Error('认证服务暂时不可用。');
    const config = await response.json();
    if (config.enabled !== true) return;
    api = url.origin;
    $('auth-status').textContent = '账号认证已开放 · 10 分钟一次性证明';
    $('auth-status').classList.add('ready');
    for (const id of ['generate', 'consent', 'verify', 'verify-code']) $(id).disabled = false;
  } catch {
    $('auth-status').textContent = '认证服务暂时不可用 · 请稍后再试';
  }
}
configure();
$('generate-form').addEventListener('submit', (event) => {
  event.preventDefault();
  if (api && $('consent').checked) location.assign(api + '/auth/start?consent=1');
});
$('verify-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!api) return;
  $('verify').disabled = true;
  message('正在核验…');
  try {
    const response = await fetch(api + '/api/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: $('verify-code').value.trim() }), cache: 'no-store', signal: AbortSignal.timeout(10000) });
    const data = await response.json();
    if (!response.ok) throw new Error(response.status === 429 ? '核验过于频繁，请稍后重试。' : '核验服务暂时不可用。若请求已抵达服务端，该码可能已被消耗。');
    if (data.valid === true) {
      message(`已核验：此证明码对应一次同济账号认证（${new Date(data.issuedAt * 1000).toLocaleString('zh-CN')}）。该码现已失效。`);
      if ($('proof-code').textContent === $('verify-code').value.trim()) clearProof();
    } else message('证明码不存在、已过期或已被核验。', true);
    $('verify-code').value = '';
  } catch (error) {
    message(error.name === 'TimeoutError' || error.name === 'TypeError' ? '网络请求未完成；若服务端已核验，该码可能已经失效，请让对方重新生成。' : error.message, true);
  } finally { $('verify').disabled = false; }
});
$('copy-proof').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('proof-code').textContent); message('已复制证明码。'); }
  catch { message('无法自动复制，请选中证明码手动复制。', true); }
});
$('forget-proof').addEventListener('click', () => { clearProof(); message('已清除本页显示。该码仍可能在有效期内被核验。'); });
$('filter').addEventListener('input', () => {
  const query = $('filter').value.trim().toLocaleLowerCase();
  let count = 0;
  document.querySelectorAll('.link-grid a').forEach((link) => {
    link.hidden = !(link.textContent + ' ' + link.href).toLocaleLowerCase().includes(query);
    if (!link.hidden) count++;
  });
  document.querySelectorAll('.block:not(.note)').forEach((block) => {
    block.hidden = !block.querySelector('.link-grid a:not([hidden])');
  });
  $('no-results').hidden = count !== 0;
  $('filter-result').textContent = `找到 ${count} 个站点。`;
});

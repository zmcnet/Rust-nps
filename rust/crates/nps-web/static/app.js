/*
 * NPS · Rust 管理台前端。
 *
 * 约束（与后端约定一致）：
 * - 用户名密码登录优先使用 HttpOnly 会话 Cookie（fetch 一律 credentials: 'same-origin'）；
 *   若后端在登录响应里返回会话令牌（当前实现），则存 sessionStorage 并以 Bearer 发送；
 * - 超级管理员令牌（NPS_ADMIN_TOKEN）只存 sessionStorage，关闭标签页即失效；
 * - 任何 API 返回 401 都立刻回到登录页并清空本地状态，绝不停留在半加载界面；
 * - 只请求当前站点的 /api，不加载任何外部资源；
 * - 所有服务端数据都用 textContent 写入 DOM，避免 XSS；
 * - 每 3 秒轮询一次状态，轮询期间不叠加请求。
 */
(function () {
  'use strict';

  /** 登录会话令牌（后端在登录响应里返回时使用）。 */
  var SESSION_KEY = 'nps.session.token';
  /** 超级管理员令牌。 */
  var ADMIN_KEY = 'nps.admin.token';
  var POLL_INTERVAL = 3000;
  var MIN_TOKEN_LEN = 24;

  var dom = {
    bootView: document.getElementById('boot-view'),
    nav: document.getElementById('main-nav'),
    main: document.getElementById('app-main'),
    loginView: document.getElementById('login-view'),
    loginForm: document.getElementById('login-form'),
    loginBtn: document.getElementById('login-btn'),
    loginError: document.getElementById('login-error'),
    loginUsername: document.getElementById('login-username'),
    loginPassword: document.getElementById('login-password'),
    tokenForm: document.getElementById('token-form'),
    tokenBtn: document.getElementById('token-btn'),
    tokenError: document.getElementById('token-error'),
    tokenInput: document.getElementById('token-input'),
    currentUser: document.getElementById('current-user'),
    logoutBtn: document.getElementById('logout-btn'),
    connStatus: document.getElementById('conn-status'),
    lastUpdated: document.getElementById('last-updated'),
    banner: document.getElementById('banner'),
    bridgeAddr: document.getElementById('bridge-addr'),
    clientsBody: document.getElementById('clients-body'),
    tunnelsBody: document.getElementById('tunnels-body'),
    clientsCount: document.getElementById('clients-count'),
    tunnelsCount: document.getElementById('tunnels-count'),
    statClientsOnline: document.getElementById('stat-clients-online'),
    statClientsHint: document.getElementById('stat-clients-hint'),
    statTunnelsEnabled: document.getElementById('stat-tunnels-enabled'),
    statTunnelsHint: document.getElementById('stat-tunnels-hint'),
    statActiveConns: document.getElementById('stat-active-conns'),
    statTraffic: document.getElementById('stat-traffic')
  };

  var state = {
    /** 后端登录接口返回的会话令牌（无 Cookie 时使用）。 */
    sessionToken: '',
    /** 超级管理员令牌。 */
    adminToken: '',
    /** 是否已通过 whoami 确认身份。 */
    authenticated: false,
    /** whoami 原始返回。 */
    identity: null,
    isAdmin: false,
    displayName: '',
    snapshot: null,
    /** 正在执行启停请求的隧道 ID，用于禁用按钮防重复提交。 */
    busyTunnels: Object.create(null),
    loading: false,
    hasLoaded: false,
    pollTimer: 0,
    errorText: ''
  };

  // -------------------------------------------------------------------------
  // 工具
  // -------------------------------------------------------------------------

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (key) {
        var value = attrs[key];
        if (value === null || value === undefined || value === false) return;
        if (key === 'text') {
          node.textContent = String(value);
        } else if (key === 'className') {
          node.className = value;
        } else if (key === 'dataset') {
          Object.keys(value).forEach(function (dataKey) {
            node.dataset[dataKey] = String(value[dataKey]);
          });
        } else {
          node.setAttribute(key, value === true ? '' : String(value));
        }
      });
    }
    if (children) {
      children.forEach(function (child) {
        if (child === null || child === undefined) return;
        node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
      });
    }
    return node;
  }

  function formatBytes(value) {
    var bytes = Number(value);
    if (!isFinite(bytes) || bytes <= 0) return '0 B';
    var units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
    var index = 0;
    while (bytes >= 1024 && index < units.length - 1) {
      bytes /= 1024;
      index += 1;
    }
    var digits = index === 0 ? 0 : bytes >= 100 ? 0 : bytes >= 10 ? 1 : 2;
    return bytes.toFixed(digits) + ' ' + units[index];
  }

  function formatNumber(value) {
    var number = Number(value);
    if (!isFinite(number)) return '0';
    return String(Math.trunc(number)).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }

  function formatTime(date) {
    function pad(n) {
      return n < 10 ? '0' + n : String(n);
    }
    return pad(date.getHours()) + ':' + pad(date.getMinutes()) + ':' + pad(date.getSeconds());
  }

  function setBanner(text) {
    state.errorText = text || '';
    if (!state.errorText) {
      dom.banner.hidden = true;
      dom.banner.textContent = '';
      return;
    }
    dom.banner.textContent = state.errorText;
    dom.banner.hidden = false;
  }

  function setConnStatus(kind, label) {
    dom.connStatus.dataset.state = kind;
    dom.connStatus.textContent = label;
  }

  /// sessionStorage 在隐私模式下可能抛异常，所有访问都必须包好。
  function readSession(key) {
    try {
      return window.sessionStorage.getItem(key) || '';
    } catch (e) {
      return '';
    }
  }

  function writeSession(key, value) {
    try {
      if (value) window.sessionStorage.setItem(key, value);
      else window.sessionStorage.removeItem(key);
    } catch (e) {
      /* 隐私模式：忽略，登录状态仅本次页面内有效 */
    }
  }

  function clearCredentials() {
    state.sessionToken = '';
    state.adminToken = '';
    writeSession(SESSION_KEY, '');
    writeSession(ADMIN_KEY, '');
  }

  function credentialToken() {
    return state.sessionToken || state.adminToken;
  }

  function tokenByteLength(value) {
    if (typeof TextEncoder === 'function') {
      return new TextEncoder().encode(value).length;
    }
    return value.length;
  }

  // -------------------------------------------------------------------------
  // 视图切换
  // -------------------------------------------------------------------------

  /// 把主界面的数据区域重置为占位内容，避免退出/失效后残留上一位用户的数据。
  function resetDataView() {
    state.snapshot = null;
    state.hasLoaded = false;
    if (dom.bridgeAddr) dom.bridgeAddr.textContent = '—';
    setStat(dom.statClientsOnline, '—');
    if (dom.statClientsHint) dom.statClientsHint.textContent = '共 — 个';
    setStat(dom.statTunnelsEnabled, '—');
    if (dom.statTunnelsHint) dom.statTunnelsHint.textContent = '共 — 条';
    setStat(dom.statActiveConns, '—');
    setStat(dom.statTraffic, '—');
    if (dom.clientsCount) dom.clientsCount.textContent = '';
    if (dom.tunnelsCount) dom.tunnelsCount.textContent = '';
    fillPlaceholder(dom.clientsBody, 4, '登录后显示客户端。');
    fillPlaceholder(dom.tunnelsBody, 8, '登录后显示隧道。');
    if (siteDom.body) {
      fillPlaceholder(siteDom.body, 7, '登录后显示站点。');
      if (siteDom.count) siteDom.count.textContent = '';
    }
    if (certDom.body) {
      fillPlaceholder(certDom.body, 7, '登录后显示证书。');
      if (certDom.count) certDom.count.textContent = '';
    }
    acmeState = null;
    if (certDom.acmeWarn) certDom.acmeWarn.textContent = '';
    if (certDom.acmeSteps) certDom.acmeSteps.replaceChildren();
    if (certDom.acmeStatus) setFormStatus(certDom.acmeStatus, '', '');
    Object.keys(state.busyTunnels).forEach(function (key) {
      delete state.busyTunnels[key];
    });
  }

  function setStat(node, text) {
    if (node) node.textContent = text;
  }

  function fillPlaceholder(body, colspan, text) {
    if (!body) return;
    body.replaceChildren(
      el('tr', { className: 'empty-row' }, [el('td', { colspan: String(colspan), text: text })])
    );
  }

  function showLogin(message) {
    stopPolling();
    state.authenticated = false;
    state.loading = false;
    setBanner('');
    resetDataView();

    if (dom.bootView) dom.bootView.hidden = true;
    dom.main.hidden = true;
    dom.nav.hidden = true;
    dom.logoutBtn.hidden = true;
    dom.logoutBtn.disabled = false;
    dom.currentUser.hidden = true;
    dom.currentUser.textContent = '';
    dom.loginView.hidden = false;
    dom.lastUpdated.textContent = '';
    setConnStatus('idle', '未登录');

    // 切换视图时清空所有错误与凭据输入，避免把上一次的内容留在页面上。
    dom.loginError.textContent = '';
    dom.loginError.hidden = true;
    dom.tokenError.textContent = '';
    dom.tokenError.hidden = true;
    dom.loginBtn.disabled = false;
    dom.loginBtn.textContent = '登录';
    dom.tokenBtn.disabled = false;
    dom.tokenBtn.textContent = '使用令牌进入';
    dom.loginPassword.value = '';
    dom.tokenInput.value = '';

    if (message) {
      dom.loginError.textContent = message;
      dom.loginError.hidden = false;
    }
  }

  function applyPermissions() {
    var nodes = document.querySelectorAll('.admin-only');
    for (var i = 0; i < nodes.length; i += 1) {
      nodes[i].hidden = !state.isAdmin;
    }
  }

  /// 兼容 cookie 模式（display/username）与当前 Bearer 模式（principal）。
  function identityDisplay(info) {
    if (!info || typeof info !== 'object') return '已登录';
    if (typeof info.display === 'string' && info.display.trim()) return info.display.trim();
    if (typeof info.username === 'string' && info.username.trim()) return info.username.trim();
    var principal = typeof info.principal === 'string' ? info.principal : '';
    if (principal === 'admin(token)') return '超级管理员（令牌）';
    if (principal) return principal;
    return '已登录';
  }

  function applyIdentity(info) {
    state.identity = info || null;
    state.isAdmin = !!(info && info.is_admin);
    state.displayName = identityDisplay(info);
    state.authenticated = true;
  }

  function enterApp(info) {
    applyIdentity(info);

    if (dom.bootView) dom.bootView.hidden = true;
    dom.loginView.hidden = true;
    dom.main.hidden = false;
    dom.nav.hidden = false;
    dom.logoutBtn.hidden = false;
    dom.logoutBtn.disabled = false;
    dom.currentUser.textContent = state.displayName;
    dom.currentUser.hidden = false;
    // 非敏感的角色提示，便于客户端账号理解界面差异。
    dom.currentUser.title = state.isAdmin ? '管理员' : '客户端账号';

    dom.loginError.textContent = '';
    dom.loginError.hidden = true;
    dom.tokenError.textContent = '';
    dom.tokenError.hidden = true;
    dom.loginPassword.value = '';
    dom.tokenInput.value = '';
    dom.loginBtn.disabled = false;
    dom.loginBtn.textContent = '登录';
    dom.tokenBtn.disabled = false;
    dom.tokenBtn.textContent = '使用令牌进入';

    applyPermissions();
    setConnStatus('ok', '已连接');
    dom.lastUpdated.textContent = '更新于 ' + formatTime(new Date());
    setBanner('');

    refresh();
    startPolling();
  }

  // -------------------------------------------------------------------------
  // API
  // -------------------------------------------------------------------------

  function AuthError(message) {
    this.name = 'AuthError';
    this.message = message || 'not authorized';
    this.status = 401;
  }
  AuthError.prototype = Object.create(Error.prototype);
  AuthError.prototype.constructor = AuthError;

  function defaultErrorMessage(status) {
    if (status === 403) return '没有权限执行此操作';
    if (status === 404) return '接口不存在';
    if (status === 429) return '尝试次数过多，请稍后再试';
    return '请求失败（HTTP ' + status + '）';
  }

  /**
   * 统一的 API 请求。
   *
   * opts:
   * - method / body：常规选项
   * - token：显式指定 Bearer 令牌（'' 表示不携带）
   * - noAuth：true 时不携带 Authorization（登录接口）
   * - handle401：false 时不把 401 抛成 AuthError（登录 / 令牌校验自处理）
   */
  function request(path, options) {
    var opts = options || {};
    var headers = { Accept: 'application/json' };
    var token = opts.noAuth
      ? ''
      : opts.token !== undefined
        ? opts.token
        : credentialToken();
    if (token) headers.Authorization = 'Bearer ' + token;
    if (opts.body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    return fetch(path, {
      method: opts.method || 'GET',
      headers: headers,
      body: opts.body,
      // 后端可能用 HttpOnly 会话 Cookie，必须带上同源凭据；
      // 纯 Bearer 时该选项无副作用。
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error'
    }).then(function (response) {
      return response
        .json()
        .catch(function () {
          return null;
        })
        .then(function (payload) {
          if (response.ok) return payload;
          var message =
            payload && typeof payload.error === 'string' && payload.error
              ? payload.error
              : defaultErrorMessage(response.status);
          if (response.status === 401 && opts.handle401 !== false) {
            throw new AuthError(message);
          }
          var error = new Error(message);
          error.status = response.status;
          error.payload = payload;
          throw error;
        });
    });
  }

  function fetchWhoami(token) {
    return request('/api/whoami', { token: token, handle401: false });
  }

  /// 所有 401 的唯一出口：清空凭据与数据，回到登录页。
  function handleAuthFailure() {
    clearCredentials();
    showLogin('登录已失效，请重新登录。');
  }

  /// 业务操作失败时的统一处理：401 回登录页，其余交给调用方渲染。
  function handleActionError(error, render) {
    if (error instanceof AuthError) {
      handleAuthFailure();
      return;
    }
    if (render) render(error);
  }

  // -------------------------------------------------------------------------
  // 轮询
  // -------------------------------------------------------------------------

  function startPolling() {
    stopPolling();
    if (!state.authenticated) return;
    state.pollTimer = window.setInterval(refresh, POLL_INTERVAL);
  }

  function stopPolling() {
    if (state.pollTimer) {
      window.clearInterval(state.pollTimer);
      state.pollTimer = 0;
    }
  }

  function refresh() {
    if (!state.authenticated || state.loading) return;
    state.loading = true;
    if (!state.hasLoaded) setConnStatus('loading', '连接中');

    request('/api/status')
      .then(function (snapshot) {
        state.snapshot = snapshot;
        state.hasLoaded = true;
        setBanner('');
        setConnStatus('ok', '已连接');
        dom.lastUpdated.textContent = '更新于 ' + formatTime(new Date());
        render();
        // 客户端账号看不到站点/证书，也不应发起这些请求（避免 403/401 噪音）。
        if (state.isAdmin) {
          refreshSites();
          refreshCerts();
          refreshAcmeSummary();
        }
      })
      .catch(function (error) {
        if (error instanceof AuthError) {
          handleAuthFailure();
          return;
        }
        setConnStatus('offline', '连接异常');
        setBanner('无法获取状态：' + (error && error.message ? error.message : '网络错误'));
      })
      .then(function () {
        state.loading = false;
      });
  }

  // -------------------------------------------------------------------------
  // 渲染
  // -------------------------------------------------------------------------

  function render() {
    var snapshot = state.snapshot;
    if (!snapshot) return;

    var clients = Array.isArray(snapshot.clients) ? snapshot.clients.slice() : [];
    var tunnels = Array.isArray(snapshot.tunnels) ? snapshot.tunnels.slice() : [];

    clients.sort(function (a, b) {
      if (!!a.online !== !!b.online) return a.online ? -1 : 1;
      return String(a.name || '').localeCompare(String(b.name || ''), 'zh-Hans-CN');
    });
    tunnels.sort(function (a, b) {
      return Number(a.id) - Number(b.id);
    });

    dom.bridgeAddr.textContent = snapshot.bridge_addr ? String(snapshot.bridge_addr) : '未监听';

    var online = clients.filter(function (client) {
      return !!client.online;
    }).length;
    var enabled = tunnels.filter(function (tunnel) {
      return !!tunnel.enabled;
    }).length;
    var activeConns = tunnels.reduce(function (sum, tunnel) {
      return sum + (Number(tunnel.active_connections) || 0);
    }, 0);
    var traffic = tunnels.reduce(function (sum, tunnel) {
      return (
        sum + (Number(tunnel.bytes_to_client) || 0) + (Number(tunnel.bytes_from_client) || 0)
      );
    }, 0);

    dom.statClientsOnline.textContent = formatNumber(online);
    dom.statClientsHint.textContent = '共 ' + formatNumber(clients.length) + ' 个';
    dom.statTunnelsEnabled.textContent = formatNumber(enabled);
    dom.statTunnelsHint.textContent = '共 ' + formatNumber(tunnels.length) + ' 条';
    dom.statActiveConns.textContent = formatNumber(activeConns);
    dom.statTraffic.textContent = formatBytes(traffic);

    renderClients(clients);
    renderTunnels(tunnels);
  }

  function renderClients(clients) {
    var body = dom.clientsBody;
    dom.clientsCount.textContent = clients.length ? '共 ' + clients.length + ' 个' : '';

    if (!clients.length) {
      body.replaceChildren(
        el('tr', { className: 'empty-row' }, [
          el('td', { colspan: '4', text: '暂无客户端。启动 nps 客户端并连接到本服务器后，会显示在这里。' })
        ])
      );
      return;
    }

    body.replaceChildren.apply(
      body,
      clients.map(function (client) {
        var online = !!client.online;
        return el('tr', null, [
          el('td', null, [
            el('div', { className: 'cell-main', text: client.name || '（未命名）' })
          ]),
          el('td', { className: 'mono muted-cell', text: String(client.id) }),
          el('td', null, [
            el('span', {
              className: 'pill',
              dataset: { state: online ? 'online' : 'off' },
              text: online ? '在线' : '离线'
            })
          ]),
          el('td', {
            className: 'mono muted-cell',
            text: client.version ? String(client.version) : '—'
          })
        ]);
      })
    );
  }

  function renderTunnels(tunnels) {
    var body = dom.tunnelsBody;
    var clientNames = Object.create(null);
    var clientOnline = Object.create(null);
    var clients = (state.snapshot && state.snapshot.clients) || [];
    clients.forEach(function (client) {
      clientNames[client.id] = client.name || '客户端 #' + client.id;
      clientOnline[client.id] = !!client.online;
    });

    dom.tunnelsCount.textContent = tunnels.length ? '共 ' + tunnels.length + ' 条' : '';

    if (!tunnels.length) {
      body.replaceChildren(
        el('tr', { className: 'empty-row' }, [
          el('td', { colspan: '8', text: '暂无隧道。启动客户端并在其配置中添加 TCP 隧道后，会显示在这里。' })
        ])
      );
      return;
    }

    body.replaceChildren.apply(
      body,
      tunnels.map(function (tunnel) {
        return renderTunnelRow(tunnel, clientNames, clientOnline);
      })
    );
  }

  function renderTunnelRow(tunnel, clientNames, clientOnline) {
    var id = Number(tunnel.id);
    var enabled = !!tunnel.enabled;
    var busy = !!state.busyTunnels[id];
    var online = clientOnline[tunnel.client_id];
    var clientLabel = clientNames[tunnel.client_id] || '客户端 #' + tunnel.client_id;

    var nameCellChildren = [el('div', { className: 'cell-main', text: tunnel.name || '隧道 #' + id })];
    nameCellChildren.push(el('div', { className: 'cell-sub mono', text: '#' + id }));
    if (tunnel.last_error) {
      nameCellChildren.push(
        el('div', {
          className: 'cell-sub cell-error',
          title: String(tunnel.last_error),
          text: '错误：' + String(tunnel.last_error)
        })
      );
    }

    var clientCellChildren = [el('div', { className: 'cell-main', text: clientLabel })];
    clientCellChildren.push(
      el('div', {
        className: 'cell-sub',
        text: online ? '在线' : '离线（连接由客户端建立）'
      })
    );

    // 客户端账号只读：不提供启停入口（后端也只按其可见客户端返回数据）。
    var actionsCell;
    if (state.isAdmin) {
      var buttonLabel = busy ? (enabled ? '停用中…' : '启用中…') : enabled ? '停用' : '启用';
      var button = el(
        'button',
        {
          type: 'button',
          className: 'btn btn-small ' + (enabled ? 'btn-stop' : 'btn-start'),
          disabled: busy
        },
        [buttonLabel]
      );
      button.addEventListener('click', function () {
        toggleTunnel(id, !enabled, button);
      });
      actionsCell = el('td', { className: 'actions' }, [button]);
    } else {
      actionsCell = el('td', { className: 'actions muted-cell', text: '—' });
    }

    return el('tr', null, [
      el('td', null, nameCellChildren),
      el('td', null, clientCellChildren),
      el('td', { className: 'mono', text: tunnel.listen_addr || '—' }),
      el('td', { className: 'mono muted-cell', text: tunnel.target_addr || '—' }),
      el('td', null, [
        el('span', {
          className: 'pill',
          dataset: { state: enabled ? 'online' : 'off' },
          text: enabled ? '已启用' : '已停用'
        })
      ]),
      el('td', { className: 'num', text: formatNumber(tunnel.active_connections) }),
      el('td', { className: 'num' }, [
        el('div', { className: 'traffic' }, [
          el('span', { text: '发送 ' + formatBytes(tunnel.bytes_to_client) }),
          el('span', { text: '接收 ' + formatBytes(tunnel.bytes_from_client) })
        ])
      ]),
      actionsCell
    ]);
  }

  // -------------------------------------------------------------------------
  // 启停
  // -------------------------------------------------------------------------

  function toggleTunnel(id, enabled, button) {
    if (state.busyTunnels[id]) return;
    state.busyTunnels[id] = true;
    button.disabled = true;
    button.textContent = enabled ? '启用中…' : '停用中…';
    setBanner('');

    request('/api/tunnels/' + encodeURIComponent(String(id)) + '/state', {
      method: 'POST',
      body: JSON.stringify({ enabled: enabled })
    })
      .then(function () {
        delete state.busyTunnels[id];
        refresh();
      })
      .catch(function (error) {
        delete state.busyTunnels[id];
        if (error instanceof AuthError) {
          handleAuthFailure();
          return;
        }
        setBanner(
          (enabled ? '启用' : '停用') +
            '隧道 #' +
            id +
            ' 失败：' +
            (error && error.message ? error.message : '网络错误')
        );
        button.disabled = false;
        button.textContent = enabled ? '启用' : '停用';
        refresh();
      });
  }

  // -------------------------------------------------------------------------
  // 登录 / 退出
  // -------------------------------------------------------------------------

  function showLoginError(text) {
    dom.loginError.textContent = text;
    dom.loginError.hidden = false;
  }

  function showTokenError(text) {
    dom.tokenError.textContent = text;
    dom.tokenError.hidden = false;
  }

  function loginWithPassword() {
    if (dom.loginBtn.disabled) return;
    var username = (dom.loginUsername.value || '').trim();
    var password = dom.loginPassword.value || '';

    dom.loginError.textContent = '';
    dom.loginError.hidden = true;
    dom.tokenError.textContent = '';
    dom.tokenError.hidden = true;

    if (!username || !password) {
      showLoginError('请输入用户名和密码。');
      return;
    }

    dom.loginBtn.disabled = true;
    dom.loginBtn.textContent = '登录中…';
    setConnStatus('loading', '登录中');

    request('/api/auth/login', {
      method: 'POST',
      noAuth: true,
      handle401: false,
      body: JSON.stringify({ username: username, password: password })
    })
      .then(function (payload) {
        // 当前后端在响应体返回会话令牌；若后端改为纯 Cookie，这里 token 为空，
        // 后续请求靠 credentials: 'same-origin' 携带 Cookie。
        var token = payload && typeof payload.token === 'string' ? payload.token : '';
        if (token) {
          state.sessionToken = token;
          writeSession(SESSION_KEY, token);
        } else {
          // 纯 Cookie 模式：不残留上一条会话令牌，避免用陈旧 Bearer 覆盖 Cookie。
          state.sessionToken = '';
          writeSession(SESSION_KEY, '');
        }
        state.adminToken = '';
        writeSession(ADMIN_KEY, '');
        return fetchWhoami(token).catch(function (error) {
          if (error) error.stage = 'whoami';
          throw error;
        });
      })
      .then(function (info) {
        enterApp(info);
      })
      .catch(function (error) {
        failLogin(error);
      });
  }

  function failLogin(error) {
    var message;
    if (error && error.status === 429) {
      message = '尝试次数过多，请稍后再试';
    } else if (error instanceof AuthError || (error && error.status === 401)) {
      if (error && error.stage === 'whoami') {
        message = '登录状态未能建立，请重试。';
      } else {
        message = (error && error.message) || '用户名或密码错误';
      }
    } else {
      message = (error && error.message) || '登录失败，请稍后重试。';
    }

    // 登录未完成：不保留任何会话令牌。
    state.sessionToken = '';
    writeSession(SESSION_KEY, '');
    state.authenticated = false;

    showLoginError(message);
    dom.loginPassword.value = '';
    dom.loginBtn.disabled = false;
    dom.loginBtn.textContent = '登录';
    setConnStatus('idle', '未登录');
  }

  function loginWithToken() {
    if (dom.tokenBtn.disabled) return;
    var candidate = (dom.tokenInput.value || '').trim();

    dom.loginError.textContent = '';
    dom.loginError.hidden = true;
    dom.tokenError.textContent = '';
    dom.tokenError.hidden = true;

    // 按 UTF-8 字节长度校验，与后端要求一致。
    if (tokenByteLength(candidate) < MIN_TOKEN_LEN) {
      showTokenError('令牌至少需要 ' + MIN_TOKEN_LEN + ' 字节。');
      return;
    }

    dom.tokenBtn.disabled = true;
    dom.tokenBtn.textContent = '验证中…';
    setConnStatus('loading', '验证中');

    state.adminToken = candidate;
    fetchWhoami(candidate)
      .then(function (info) {
        state.sessionToken = '';
        writeSession(SESSION_KEY, '');
        writeSession(ADMIN_KEY, candidate);
        enterApp(info);
      })
      .catch(function (error) {
        state.adminToken = '';
        writeSession(ADMIN_KEY, '');
        var message;
        if (error && error.status === 401) {
          message = '令牌无效，请检查服务端 NPS_ADMIN_TOKEN 配置。';
        } else {
          message = '无法连接管理服务：' + ((error && error.message) || '网络错误');
        }
        showTokenError(message);
        dom.tokenBtn.disabled = false;
        dom.tokenBtn.textContent = '使用令牌进入';
        setConnStatus('idle', '未登录');
      });
  }

  function logout(showMessage) {
    var token = credentialToken();
    stopPolling();
    dom.logoutBtn.disabled = true;

    if (!state.authenticated) {
      clearCredentials();
      dom.logoutBtn.disabled = false;
      showLogin('');
      return;
    }

    var finish = function () {
      dom.logoutBtn.disabled = false;
      clearCredentials();
      showLogin(showMessage ? '已退出登录。' : '');
    };

    // 即使服务端登出失败，也要清理本地状态（Cookie 由服务端负责清除）。
    request('/api/auth/logout', {
      method: 'POST',
      token: token,
      handle401: false
    })
      .catch(function () {})
      .then(function () {
        // 若同时存在 Cookie 会话（后端返回过令牌的场景），再发一次不带
        // Authorization 的登出，确保 Cookie 会话也被清除。纯 Bearer 后端
        // 对这个请求同样返回 200，无副作用。
        if (!token) return null;
        return request('/api/auth/logout', {
          method: 'POST',
          token: '',
          handle401: false
        }).catch(function () {});
      })
      .then(finish);
  }

  function bindNav() {
    function activate(hash) {
      var links = dom.nav.querySelectorAll('a');
      for (var i = 0; i < links.length; i += 1) {
        var link = links[i];
        var target = link.getAttribute('href');
        link.setAttribute('aria-current', target === hash ? 'true' : 'false');
      }
    }
    window.addEventListener('hashchange', function () {
      activate(window.location.hash);
    });
    activate(window.location.hash || '#overview');
  }

  function restoreSession() {
    state.sessionToken = readSession(SESSION_KEY);
    state.adminToken = readSession(ADMIN_KEY);
    var token = credentialToken();
    setConnStatus('loading', '检查中');

    // 页面加载时先问后端「我是谁」：有 Cookie/Bearer 就进主界面，否则显示登录页。
    fetchWhoami(token)
      .then(function (info) {
        enterApp(info);
      })
      .catch(function (error) {
        var hadCredential = !!token;
        clearCredentials();
        var message = '';
        if (error && error.status === 401) {
          if (hadCredential) message = '登录已失效，请重新登录。';
        } else if (error) {
          message = '无法连接管理服务：' + ((error && error.message) || '网络错误');
        }
        showLogin(message);
      });
  }

  // -------------------------------------------------------------------------
  // 初始化
  // -------------------------------------------------------------------------

  function init() {
    dom.loginForm.addEventListener('submit', function (event) {
      event.preventDefault();
      loginWithPassword();
    });

    dom.tokenForm.addEventListener('submit', function (event) {
      event.preventDefault();
      loginWithToken();
    });

    dom.logoutBtn.addEventListener('click', function () {
      logout(true);
    });

    document.addEventListener('visibilitychange', function () {
      if (document.hidden) {
        stopPolling();
      } else if (state.authenticated) {
        refresh();
        startPolling();
      }
    });

    window.addEventListener('online', function () {
      if (state.authenticated) refresh();
    });

    bindNav();
    bindSites();
    bindCerts();

    restoreSession();
  }

  // -------------------------------------------------------------------------
  // 站点管理
  // -------------------------------------------------------------------------
  var siteDom = {};
  var certDom = {};
  var acmeState = null;

  function bindSites() {
    siteDom.body = document.getElementById('sites-body');
    siteDom.count = document.getElementById('sites-count');
    siteDom.form = document.getElementById('site-form');
    siteDom.domain = document.getElementById('site-domain');
    siteDom.client = document.getElementById('site-client');
    siteDom.target = document.getElementById('site-target');
    siteDom.ws = document.getElementById('site-ws');
    siteDom.status = document.getElementById('site-status');
    if (!siteDom.form) return;

    siteDom.form.addEventListener('submit', function (event) {
      event.preventDefault();
      var domain = (siteDom.domain.value || '').trim();
      var target = (siteDom.target.value || '').trim();
      var clientId = parseInt(siteDom.client.value, 10);
      // 先清空上一次的状态，避免提交失败时仍显示上一次的"已保存"
      setFormStatus(siteDom.status, '', '');
      if (!domain || !target || !isFinite(clientId)) {
        setFormStatus(siteDom.status, 'err', '域名、客户端 ID、目标地址都必填');
        return;
      }
      setFormStatus(siteDom.status, 'busy', '保存中…');
      request('/api/sites', {
        method: 'POST',
        body: JSON.stringify({
          domain: domain,
          client_id: clientId,
          target: target,
          routes: [],
          websocket: !!siteDom.ws.checked
        })
      })
        .then(function (view) {
          setFormStatus(siteDom.status, 'ok', '已保存：' + view.domain);
          refreshSites();
        })
        .catch(function (error) {
          handleActionError(error, function (err) {
            setFormStatus(siteDom.status, 'err', describeError(err));
          });
        });
    });
  }

  function refreshSites() {
    if (!siteDom.body || !state.authenticated || !state.isAdmin) return;
    request('/api/sites')
      .then(function (sites) {
        renderSites(Array.isArray(sites) ? sites : []);
      })
      .catch(function (error) {
        // 轮询失败不打断主界面，但 401 必须回登录页。
        if (error instanceof AuthError) handleAuthFailure();
      });
  }

  function renderSites(sites) {
    var body = siteDom.body;
    if (siteDom.count) {
      siteDom.count.textContent = sites.length ? '共 ' + sites.length + ' 个' : '';
    }
    while (body.firstChild) body.removeChild(body.firstChild);
    if (!sites.length) {
      appendEmptyRow(body, 7, '还没有站点。用下方表单添加第一个域名。');
      return;
    }
    sites.forEach(function (site) {
      var tr = document.createElement('tr');
      appendCell(tr, site.domain);
      appendCell(tr, '#' + site.client_id);
      appendCell(tr, site.target);
      var routes = (site.routes || []).map(function (r) {
        return r.prefix + ' → ' + r.target;
      });
      appendCell(tr, routes.length ? routes.join('，') : '—');
      appendCell(tr, site.websocket ? '允许' : '禁止');
      appendCell(tr, '—');

      var actions = document.createElement('td');
      actions.className = 'actions-col';
      var del = document.createElement('button');
      del.className = 'btn btn-ghost btn-sm';
      del.type = 'button';
      del.textContent = '删除';
      del.addEventListener('click', function () {
        if (!window.confirm('删除站点 ' + site.domain + '？')) return;
        request('/api/sites/' + encodeURIComponent(site.domain), { method: 'DELETE' })
          .then(function () {
            refreshSites();
          })
          .catch(function (error) {
            handleActionError(error, function (err) {
              setFormStatus(siteDom.status, 'err', describeError(err));
            });
          });
      });
      actions.appendChild(del);
      tr.appendChild(actions);
      body.appendChild(tr);
    });
  }

  // -------------------------------------------------------------------------
  // 证书管理
  // -------------------------------------------------------------------------
  function bindCerts() {
    certDom.body = document.getElementById('certs-body');
    certDom.count = document.getElementById('certs-count');
    certDom.domain = document.getElementById('cert-domain');
    certDom.pem = document.getElementById('cert-pem');
    certDom.key = document.getElementById('cert-key');
    certDom.status = document.getElementById('cert-status');
    certDom.uploadBtn = document.getElementById('cert-upload-btn');
    certDom.uploadPanel = document.getElementById('cert-upload-panel');
    certDom.selfPanel = document.getElementById('cert-selfsigned-panel');
    certDom.acmePanel = document.getElementById('cert-acme-panel');
    certDom.selfDomain = document.getElementById('cert-self-domain');
    certDom.selfBtn = document.getElementById('cert-self-btn');
    certDom.acmeDomain = document.getElementById('cert-acme-domain');
    certDom.acmeBtn = document.getElementById('cert-acme-btn');
    certDom.acmeStatus = document.getElementById('cert-acme-status');
    certDom.acmeWarn = document.getElementById('cert-acme-warn');
    certDom.acmeSteps = document.getElementById('acme-steps');
    certDom.reloadBtn = document.getElementById('cert-reload-btn');
    if (!certDom.body) return;

    var modes = document.querySelectorAll('input[name="tls-mode"]');
    Array.prototype.forEach.call(modes, function (radio) {
      radio.addEventListener('change', switchCertMode);
    });
    switchCertMode();

    if (certDom.uploadBtn) {
      certDom.uploadBtn.addEventListener('click', function () {
        var domain = (certDom.domain.value || '').trim();
        var pem = certDom.pem.value || '';
        var key = certDom.key.value || '';
        if (!domain || !pem.trim() || !key.trim()) {
          setFormStatus(certDom.status, 'err', '域名、证书、私钥都必填');
          return;
        }
        setFormStatus(certDom.status, 'busy', '上传中…');
        request('/api/certs/upload', {
          method: 'POST',
          body: JSON.stringify({ domain: domain, cert_pem: pem, key_pem: key })
        })
          .then(function (view) {
            setFormStatus(certDom.status, 'ok', '已部署：' + view.domain);
            certDom.key.value = '';
            refreshCerts();
          })
          .catch(function (error) {
            handleActionError(error, function (err) {
              setFormStatus(certDom.status, 'err', describeError(err));
            });
          });
      });
    }

    if (certDom.selfBtn) {
      certDom.selfBtn.addEventListener('click', function () {
        var domain = (certDom.selfDomain.value || '').trim();
        if (!domain) {
          setFormStatus(certDom.status, 'err', '请填域名');
          return;
        }
        request('/api/certs/self-signed', {
          method: 'POST',
          body: JSON.stringify({ domain: domain })
        })
          .then(function (view) {
            setFormStatus(certDom.status, 'ok', '已生成自签证书：' + view.domain);
            refreshCerts();
          })
          .catch(function (error) {
            handleActionError(error, function (err) {
              setFormStatus(certDom.status, 'err', describeError(err));
            });
          });
      });
    }

    if (certDom.acmeBtn) {
      certDom.acmeBtn.addEventListener('click', function () {
        var domain = (certDom.acmeDomain.value || '').trim();
        if (!domain) {
          setFormStatus(certDom.acmeStatus, 'err', '请填域名');
          return;
        }
        if (!acmeState) {
          // 摘要还没拿到（可能是网络慢），先拉一次再让用户重试，
          // 不要误导用户去查服务端配置
          setFormStatus(certDom.acmeStatus, 'busy', '正在获取 ACME 状态，请稍后重试…');
          refreshAcmeSummary();
          return;
        }
        if (!acmeState.available) {
          setFormStatus(
            certDom.acmeStatus,
            'err',
            'ACME 服务不可用（服务端未初始化），请查看服务端日志'
          );
          return;
        }
        setFormStatus(certDom.acmeStatus, 'busy', '正在申请…');
        request('/api/certs/acme-request', {
          method: 'POST',
          body: JSON.stringify({ domain: domain })
        })
          .then(function (result) {
            // 后端把「预检/验证失败」设计成 200 + issued:false + reason，
            // 不是 HTTP 错误。这里必须读 issued 与 reason，
            // 否则会把失败显示成绿色成功（比不报错更危险）。
            if (result && result.issued) {
              setFormStatus(certDom.acmeStatus, 'ok', '证书已签发并部署');
              refreshCerts();
            } else {
              var reason = (result && result.reason) || '申请未成功，请查看服务端日志';
              setFormStatus(certDom.acmeStatus, 'err', '申请失败：' + reason);
              // 把原因也写进步骤列表，便于长文本阅读
              if (certDom.acmeSteps) {
                certDom.acmeSteps.textContent = '';
                var li = document.createElement('li');
                li.textContent = reason;
                certDom.acmeSteps.appendChild(li);
              }
            }
          })
          .catch(function (error) {
            handleActionError(error, function (err) {
              setFormStatus(certDom.acmeStatus, 'err', describeError(err));
            });
          });
      });
    }

    if (certDom.reloadBtn) {
      certDom.reloadBtn.addEventListener('click', function () {
        request('/api/certs/reload', { method: 'POST' })
          .then(function (result) {
            setFormStatus(certDom.status, 'ok', '已重新加载 ' + (result.loaded || 0) + ' 张证书');
            refreshCerts();
          })
          .catch(function (error) {
            handleActionError(error, function (err) {
              setFormStatus(certDom.status, 'err', describeError(err));
            });
          });
      });
    }

    // 注意：这里**不**发 /api/acme 请求。
    // bindCerts() 在登录前就执行，此时没有凭据，请求会 401 且被静默吞掉，
    // 导致 acmeState 永远为 null、ACME 申请入口 100% 不可用。
    // 改为登录成功后由 refreshAcmeSummary() 拉取。
  }

  /// 拉取 ACME 摘要并填充面板提示（必须已登录且是管理员）。
  function refreshAcmeSummary() {
    if (!state.authenticated || !state.isAdmin || !certDom.acmeWarn) return;
    request('/api/acme')
      .then(function (summary) {
        acmeState = summary;
        if (!summary.available) {
          certDom.acmeWarn.textContent =
            'ACME 服务不可用（服务端未初始化）。请检查服务端日志。';
        } else if (!summary.contact_email_set) {
          certDom.acmeWarn.textContent =
            'CA：' + summary.provider + '　验证方式：' + summary.challenge +
            '　自动续期：' + (summary.auto_renew ? '开启' : '关闭') +
            '　（尚未配置联系邮箱 acme.contact_email，部分 CA 会拒绝申请）';
        } else {
          certDom.acmeWarn.textContent =
            'CA：' + summary.provider + '　验证方式：' + summary.challenge +
            '　自动续期：' + (summary.auto_renew ? '开启' : '关闭');
        }
      })
      .catch(function (error) {
        if (error instanceof AuthError) {
          handleAuthFailure();
          return;
        }
        certDom.acmeWarn.textContent = '无法获取 ACME 状态：' + describeError(error);
      });
  }

  function switchCertMode() {
    var checked = document.querySelector('input[name="tls-mode"]:checked');
    var mode = checked ? checked.value : 'upload';
    if (certDom.uploadPanel) certDom.uploadPanel.hidden = mode !== 'upload';
    if (certDom.selfPanel) certDom.selfPanel.hidden = mode !== 'self-signed';
    if (certDom.acmePanel) certDom.acmePanel.hidden = mode !== 'acme';
  }

  function refreshCerts() {
    if (!certDom.body || !state.authenticated || !state.isAdmin) return;
    request('/api/certs')
      .then(function (certs) {
        renderCerts(Array.isArray(certs) ? certs : []);
      })
      .catch(function (error) {
        if (error instanceof AuthError) handleAuthFailure();
      });
  }

  function renderCerts(certs) {
    var body = certDom.body;
    if (certDom.count) {
      certDom.count.textContent = certs.length ? '共 ' + certs.length + ' 张' : '';
    }
    while (body.firstChild) body.removeChild(body.firstChild);
    if (!certs.length) {
      appendEmptyRow(body, 7, '还没有证书。用下方表单上传或申请。');
      return;
    }
    certs.forEach(function (cert) {
      var tr = document.createElement('tr');
      appendCell(tr, cert.domain);
      appendCell(tr, cert.source);
      appendCell(tr, cert.issuer || '—');
      appendCell(tr, cert.not_after || '—');

      var days = document.createElement('td');
      days.className = 'num';
      days.textContent = String(cert.days_remaining);
      if (cert.expired) days.setAttribute('data-state', 'off');
      else if (cert.days_remaining <= 14) days.setAttribute('data-state', 'warn');
      tr.appendChild(days);

      var stateCell = document.createElement('td');
      if (cert.expired) stateCell.textContent = '已过期';
      else if (cert.last_error) stateCell.textContent = '有错误：' + cert.last_error;
      else stateCell.textContent = '正常';
      tr.appendChild(stateCell);

      var actions = document.createElement('td');
      actions.className = 'actions-col';
      var del = document.createElement('button');
      del.className = 'btn btn-ghost btn-sm';
      del.type = 'button';
      del.textContent = '删除';
      del.addEventListener('click', function () {
        if (!window.confirm('删除 ' + cert.domain + ' 的证书？删除后该域名握手会被拒绝。')) return;
        request('/api/certs/' + encodeURIComponent(cert.domain), { method: 'DELETE' })
          .then(function () {
            refreshCerts();
          })
          .catch(function (error) {
            handleActionError(error, function (err) {
              setFormStatus(certDom.status, 'err', describeError(err));
            });
          });
      });
      actions.appendChild(del);
      tr.appendChild(actions);
      body.appendChild(tr);
    });
  }

  /// 纯 DOM 构造的空态行（项目约定：服务端数据一律走 textContent）。
  function appendEmptyRow(body, colspan, text) {
    var tr = document.createElement('tr');
    tr.className = 'empty-row';
    var td = document.createElement('td');
    td.colSpan = colspan;
    td.textContent = text;
    tr.appendChild(td);
    body.appendChild(tr);
  }

  function appendCell(row, text) {
    var td = document.createElement('td');
    td.textContent = text === undefined || text === null ? '' : String(text);
    row.appendChild(td);
  }

  function setFormStatus(el, kind, text) {
    if (!el) return;
    el.textContent = text || '';
    el.setAttribute('data-state', kind || '');
  }

  function describeError(error) {
    if (!error) return '操作失败';
    if (error instanceof AuthError || error.status === 401) return '登录已失效，请重新登录';
    return error.message || '操作失败';
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

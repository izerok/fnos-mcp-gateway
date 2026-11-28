/* fnOS panel — M2 HTMX enhancement layer.
   All panel interactions are HTMX (hx-get/hx-post + fragment swaps);
   this file only adds what HTMX cannot do on its own:
   - CSRF header on every HTMX request
   - 4xx/409 error fragments: HTMX does not swap them by default, so
     responseError inserts them (role=alert is in the fragment)
   - focus trap + focus return + background inert for drawer/modals
   - aria-pressed on filter chips, aria-live announcements
   - clipboard helpers, panel logout, logout-confirm wiring
   If HTMX fails to load, the buttons degrade to plain links/buttons
   and this file does nothing (no fake HTMX is bundled). */
(function () {
  if (typeof htmx === "undefined") return;
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const csrf = () => { const m = document.querySelector('meta[name="csrf-token"]'); return m ? m.content : ""; };
  let toastTimer = null;
  function toast(msg, isErr) {
    const el = $("#toast"); if (!el) return;
    el.textContent = msg; el.classList.toggle("err", !!isErr); el.classList.add("on");
    clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove("on"), 3400);
  }
  function announce(msg) {
    const el = $("#liveRegion"); if (el) el.textContent = msg;
  }
  function toastAndAnnounce(msg, isErr) { toast(msg, isErr); announce(msg); }

  /* -- clipboard -------------------------------------------------------
     The panel is commonly opened over plain HTTP on a LAN IP, which is
     not a secure context, so navigator.clipboard does not exist there.
     Fall back to a temporary textarea + execCommand; callers may supply
     an onFail callback that selects/expands the payload for manual copy. */
  function copyFallback(text) {
    let ta = null;
    const prev = document.activeElement;
    try {
      ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.setAttribute("aria-hidden", "true");
      ta.tabIndex = -1;
      ta.style.cssText =
        "position:fixed;top:0;left:-9999px;width:1px;height:1px;padding:0;border:0;opacity:0";
      /* iOS Safari needs the node to be editable for the selection to
         stick, while readOnly keeps the software keyboard closed. */
      if (/iPhone|iPad|iPod/i.test(navigator.userAgent || "")) {
        ta.contentEditable = "true";
        ta.readOnly = true;
      }
      document.body.appendChild(ta);
      ta.select();
      ta.setSelectionRange(0, text.length);
      return document.execCommand("copy");
    } catch (_) {
      return false;
    } finally {
      if (ta) ta.remove();
      if (prev && document.contains(prev)) prev.focus();
    }
  }
  async function copyText(text) {
    if (!text) return false;
    if (navigator.clipboard && window.isSecureContext) {
      try { await navigator.clipboard.writeText(text); return true; } catch (_) {}
    }
    return copyFallback(text);
  }
  function selectNode(el) {
    try {
      const range = document.createRange();
      range.selectNodeContents(el);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    } catch (_) {}
  }
  function copyButton(btn, text, opts) {
    const o = opts || {};
    copyText(text).then((ok) => {
      if (!ok) {
        if (o.onFail) { o.onFail(); return; }
        toastAndAnnounce(o.failMsg || "复制失败，请手动选择文本。", true);
        return;
      }
      if (!btn.dataset.label) btn.dataset.label = btn.textContent;
      btn.textContent = "已复制";
      btn.classList.add("copied");
      clearTimeout(btn._copyTimer);
      btn._copyTimer = setTimeout(() => {
        if (!document.contains(btn)) return;
        btn.textContent = btn.dataset.label;
        btn.classList.remove("copied");
      }, 1800);
      toastAndAnnounce(o.okMsg || "已复制到剪贴板。");
    });
  }

  /* Last-resort reveal for the list-page copy buttons when both clipboard
     paths fail: show the fetched text in the admin modal, selected. */
  function showSecretText(title, hint, text) {
    const body = $("#adminModalBody"); if (!body) return;
    body.replaceChildren();
    const wrap = document.createElement("div");
    const kicker = document.createElement("div");
    kicker.className = "kicker"; kicker.textContent = "访问密钥";
    const heading = document.createElement("h3");
    heading.id = "adminTitle"; heading.textContent = title;
    const note = document.createElement("p");
    note.className = "field-hint"; note.textContent = hint;
    const pre = document.createElement("pre");
    pre.className = "token-config"; pre.tabIndex = 0; pre.textContent = text;
    const actions = document.createElement("div");
    actions.className = "actions form-actions";
    const close = document.createElement("button");
    close.className = "btn"; close.type = "button";
    close.dataset.close = "admin"; close.textContent = "关闭";
    actions.append(close);
    wrap.append(kicker, heading, note, pre, actions);
    body.append(wrap);
    showAdminModal();
    selectNode(pre); pre.focus();
    announce("自动复制失败，已展开内容，请手动复制。");
  }

  async function copyTokenSecret(btn, mode) {
    const id = btn.dataset.id;
    if (!id) return;
    btn.disabled = true;
    try {
      const resp = await fetch(`/api/tokens/${encodeURIComponent(id)}/secret`, {
        headers: { Accept: "application/json" }, credentials: "same-origin",
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        const code = data && data.error && data.error.code;
        if (code === "token.unavailable") {
          toastAndAnnounce("这把密钥创建于旧版本或会话密钥已更换，轮换后可复制。", true);
        } else if (code === "auth.required") {
          toastAndAnnounce("登录已失效，请重新登录面板。", true);
        } else {
          toastAndAnnounce("读取密钥失败，请稍后重试。", true);
        }
        return;
      }
      const text = mode === "config" ? data.config : data.key;
      if (!text) { toastAndAnnounce("没有可复制的内容。", true); return; }
      copyButton(btn, text, {
        okMsg: mode === "config" ? "MCP JSON 已复制（含密钥）。" : "密钥已复制，可粘贴到客户端。",
        onFail: () => showSecretText(
          mode === "config" ? "MCP 客户端配置" : "密钥",
          "自动复制失败，已选中内容，请按 Ctrl+C 或长按复制。", text),
      });
    } catch (_) {
      toastAndAnnounce("读取密钥失败，请检查网络后重试。", true);
    } finally {
      btn.disabled = false;
    }
  }

  document.body.addEventListener("htmx:configRequest", (e) => {
    e.detail.headers["X-CSRF-Token"] = csrf();
  });

  /* -- overlays: focus trap + return focus + background inert -------- */
  let lastFocused = null;
  const FOCUSABLE = "button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])";
  function setBackgroundInert(on) {
    const page = $(".page"), bar = $(".topbar");
    if (page) page.inert = on;
    if (bar) bar.inert = on;
  }
  function trapTab(container, e) {
    const items = $$(FOCUSABLE, container).filter((el) => !el.disabled && el.offsetParent !== null);
    if (!items.length) return;
    const first = items[0], last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }
  function openOverlay(el, focusSel) {
    lastFocused = document.activeElement;
    setBackgroundInert(true);
    el.classList.add("on");
    el.setAttribute("aria-hidden", "false");
    const target = focusSel ? $(focusSel, el) : $(FOCUSABLE, el);
    if (target) target.focus();
  }
  function closeOverlay(el, hide) {
    el.classList.remove("on");
    el.setAttribute("aria-hidden", "true");
    if (hide) el.hidden = true;
    setBackgroundInert(false);
    if (lastFocused && document.contains(lastFocused)) lastFocused.focus();
    lastFocused = null;
  }
  function openDrawer() {
    const drawer = $("#drawer"); if (!drawer) return;
    lastFocused = document.activeElement;
    setBackgroundInert(true);
    drawer.classList.add("on"); drawer.setAttribute("aria-hidden", "false");
    $("#scrim").classList.add("on");
    const close = $("#drawerClose"); if (close) close.focus();
  }
  function closeDrawer() {
    const drawer = $("#drawer"); if (!drawer) return;
    drawer.classList.remove("on"); drawer.setAttribute("aria-hidden", "true");
    $("#scrim").classList.remove("on");
    setBackgroundInert(false);
    if (lastFocused && document.contains(lastFocused)) lastFocused.focus();
    lastFocused = null;
  }
  function showLoginModal() {
    const modal = $("#loginModal"); if (!modal) return;
    modal.hidden = false;
    openOverlay(modal, "#loginModalBody button, #loginModalBody a, #loginModalBody input");
  }
  function hideLoginModal() {
    const modal = $("#loginModal"); if (!modal) return;
    closeOverlay(modal, true);
  }
  /* One confirm dialog, two callers: 本机退出 (logout) and 删除机器.
     The caller supplies the copy, the hx-post target and the success
     toast; the afterRequest handler below toasts opts.toast. */
  function showConfirmModal(opts) {
    const modal = $("#confirmModal"); if (!modal) return;
    $("#confirmKicker").textContent = opts.kicker;
    $("#confirmTitle").textContent = opts.title;
    $("#confirmText").textContent = opts.body;
    const ok = $("#confirmOk");
    ok.textContent = opts.okLabel;
    ok.setAttribute("hx-post", opts.post);
    ok.setAttribute("hx-target", opts.target);
    ok.setAttribute("hx-swap", opts.swap || "innerHTML");
    ok.dataset.successToast = opts.toast;
    htmx.process(ok);
    modal.hidden = false;
    openOverlay(modal, "#confirmOk");
  }
  function hideConfirmModal() {
    const modal = $("#confirmModal"); if (!modal) return;
    closeOverlay(modal, true);
  }
  function showProfileModal() {
    const modal = $("#profileModal"); if (!modal) return;
    modal.hidden = false;
    const focusSel = "#profileModalBody input:not([type='hidden']):not([readonly]), #profileModalBody select, #profileModalBody .btn";
    openOverlay(modal, focusSel);
    /* HTMX restores focus after its swap; defer so the dialog wins. */
    setTimeout(() => {
      if (modal.hidden || modal.contains(document.activeElement)) return;
      const target = $(focusSel, modal);
      if (target) target.focus();
    }, 0);
  }
  function hideProfileModal() {
    const modal = $("#profileModal"); if (!modal) return;
    closeOverlay(modal, true);
  }
  function showAdminModal() {
    const modal = $("#adminModal"); if (!modal) return;
    modal.hidden = false;
    openOverlay(modal, "#adminModalBody button, #adminModalBody a, #adminModalBody input");
  }
  function hideAdminModal() {
    const modal = $("#adminModal"); if (!modal) return;
    /* Every open path swaps fresh content into this body, so emptying it
       on close is safe. It removes the one-time plaintext key (and any
       typed current password) instead of leaving it in a hidden DOM. */
    const body = $("#adminModalBody");
    if (body) body.replaceChildren();
    closeOverlay(modal, true);
  }
  function wireProfileForm() {
    const scheme = $("#profileScheme");
    const hint = $("#httpHint");
    if (!scheme || !hint) return;
    const update = () => {
      hint.textContent = scheme.value === "http"
        ? "已选择 HTTP：保存前必须勾选“允许 HTTP 明文连接”。"
        : "选择 HTTP 时必须勾选；明文传输可能被同一网络窃听。";
    };
    scheme.addEventListener("change", update);
    update();
  }

  /* -- HTMX lifecycle -------------------------------------------------- */
  document.body.addEventListener("htmx:afterSwap", (e) => {
    const target = e.detail.target;
    if (!target) return;
    if (target.id === "loginModalBody") {
      showLoginModal();
      const body = $("#loginModalBody");
      if (body && body.querySelector(".inline-error")) {
        announce(body.querySelector(".inline-error p")?.textContent || "授权链接被拒绝。");
      } else {
        announce("登录弹窗已打开，请在浏览器中授权。");
      }
      wireLoginModal();
    }
    if (target.id === "drawerContent") { openDrawer(); announce("诊断已打开。"); }
    if (target.id === "profileModalBody") {
      const saved = target.querySelector("[data-profile-saved]");
      if (saved) {
        hideProfileModal();
        toastAndAnnounce(saved.dataset.profileStatus === "created"
          ? "机器已添加。" : "机器配置已更新。");
      } else {
        showProfileModal();
        wireProfileForm();
        announce("机器配置表单已打开。");
      }
    }
    if (target.id === "rows") {
      const n = $$(".row", target).length;
      announce(`机器列表已更新，共 ${n} 台。`);
    }
    if (target.id === "topologyBody") {
      /* FR-36: topology is fetched on demand only; afterwards the button
         toggles visibility with zero extra requests. htmx bound a click
         listener for the initial hx-get on the element itself — such a
         listener runs BEFORE any document-level stopPropagation could
         cancel it, so every later click would re-fetch. Replacing the
         node with a clone drops that listener; the delegated click
         handler below then owns every subsequent click. */
      const body = target;
      const btn = $("#topologyBtn");
      body.hidden = false;
      body.dataset.loaded = "1";
      if (btn) {
        btn.textContent = "隐藏拓扑";
        btn.setAttribute("aria-expanded", "true");
        const fresh = btn.cloneNode(true);
        btn.replaceWith(fresh);
      }
      announce(`拓扑已加载，共 ${$$(".topo-link", body).length} 台。`);
    }
    if (target.id === "adminModalBody") {
      /* Agent key forms, the one-time plaintext view and the password
         form all swap into this body. */
      const created = target.querySelector("[data-token-created]");
      const saved = target.querySelector("[data-token-saved]");
      const pwSaved = target.querySelector("[data-password-saved]");
      const settingsSaved = target.querySelector("[data-settings-saved]");
      if (created) {
        showAdminModal();
        const copy = $("#copyTokenBtn");
        if (copy) copy.focus();
        announce("密钥已生成，请立即复制保存，关闭后不可再查看。");
      } else if (saved) {
        hideAdminModal();
        toastAndAnnounce("密钥已保存。");
      } else if (pwSaved) {
        hideAdminModal();
        toastAndAnnounce("面板密码已更新，其他会话已失效。");
      } else if (settingsSaved) {
        /* Settings stay open so the operator sees the confirmation and
           can keep tuning; the form is re-rendered with current values. */
        showAdminModal();
        toastAndAnnounce("设置已保存并生效。");
      } else if (target.childElementCount) {
        /* HTMX may fire a follow-up afterSwap for this target while it
           resolves an out-of-band fragment; by then hideAdminModal() has
           already emptied the body. An empty body means "closed" — never
           re-open a blank modal. */
        showAdminModal();
        announce("已打开面板设置。");
      }
    }
    if (target.id === "tokenRows") {
      const n = $$(".token-row", target).length;
      announce(`访问密钥已更新，共 ${n} 把。`);
    }
    if (target.id === "roster") {
      /* An OOB roster from a profile save must not announce a scan. */
      if (target.dataset.oob === "1") return;
      /* A roster rendered as the answer to a delete is announced by
         the confirm handler already; do not call it a scan. */
      if (target.dataset.deleted) return;
      const big = $("#bigOk");
      announce(big ? `扫描完成，${big.textContent} 台已连接。` : "扫描完成。");
      const busy = $("#probeBusy");
      if (busy && busy.dataset.busy) {
        toastAndAnnounce(`以下机器正在测试网络，请稍后再试：${busy.dataset.busy}`, true);
      }
    }
  });

  document.body.addEventListener("htmx:afterRequest", (e) => {
    const elt = e.detail.elt;
    if (elt && elt.id === "confirmOk" && e.detail.xhr.status === 200) {
      const target = e.detail.target;
      if (target && target.id === "adminModalBody") {
        /* Rotation opens the admin modal with the new plaintext; close
           the confirm card without undoing the admin modal's inert. */
        const modal = $("#confirmModal");
        if (modal) {
          modal.hidden = true;
          modal.classList.remove("on");
          modal.setAttribute("aria-hidden", "true");
        }
        toastAndAnnounce(elt.dataset.successToast || "操作完成。");
      } else {
        hideConfirmModal();
        toastAndAnnounce(elt.dataset.successToast || "操作完成。");
      }
    }
    /* Login finish form swaps #rows on success; close the modal. */
    if (e.detail.target && e.detail.target.id === "rows" &&
        elt && elt.tagName === "FORM" && e.detail.xhr.status === 200) {
      hideLoginModal(); toastAndAnnounce("登录完成，已连接。");
    }
  });

  /* 4xx/409: HTMX does not swap error responses; insert the fragment
     (it carries role=alert + data-error-code) next to its target. */
  document.body.addEventListener("htmx:responseError", (e) => {
    const xhr = e.detail.xhr;
    const target = e.detail.target;
    const html = xhr.responseText || "";
    if (target && target.id === "loginModalBody") {
      target.innerHTML = html; showLoginModal();
      announce("授权链接被拒绝。");
      return;
    }
    if (target && target.id === "profileModalBody") {
      target.innerHTML = html; showProfileModal(); wireProfileForm();
      const msg = target.querySelector(".inline-error p, .field-error");
      announce(msg ? msg.textContent : "保存失败，请检查表单。");
      return;
    }
    if (target && target.id === "adminModalBody") {
      target.innerHTML = html; showAdminModal();
      const msg = target.querySelector(".inline-error p, .field-error");
      announce(msg ? msg.textContent : "保存失败，请检查表单。");
      return;
    }
    const row = target && target.closest ? target.closest(".row") : null;
    if (row && html) {
      const tmp = document.createElement("div"); tmp.innerHTML = html.trim();
      const frag = tmp.firstElementChild;
      if (frag) { row.after(frag); setTimeout(() => frag.remove(), 8000); }
    }
    const code = (html.match(/data-error-code="([^"]+)"/) || [])[1] || `HTTP ${xhr.status}`;
    toastAndAnnounce(`操作失败（${code}），请稍后再试。`, true);
  });

  /* -- clicks (delegation; HTMX handles the requests themselves) ------ */
  document.addEventListener("click", (e) => {
    const chip = e.target.closest(".chip");
    if (chip) {
      $$(".chip").forEach((c) => {
        const on = c === chip;
        c.classList.toggle("active", on);
        c.setAttribute("aria-pressed", on ? "true" : "false");
      });
      return;
    }
    const actEl = e.target.closest("[data-act]");
    if (actEl && actEl.dataset.act === "logout") {
      showConfirmModal({
        kicker: "本机操作", title: `本机退出 ${actEl.dataset.id}？`,
        body: "只清除这个容器里的 session，NAS 端的授权仍然有效。共用这个 profile 的其他客户端也会掉线。",
        post: `/api/profiles/${actEl.dataset.id}/logout`, target: "#rows",
        okLabel: "本机退出", toast: "已清除本机 session。",
      });
      return;
    }
    if (actEl && actEl.dataset.act === "delete") {
      showConfirmModal({
        kicker: "删除机器", title: `删除 ${actEl.dataset.id}？`,
        body: "这台机器会从面板配置中移除，已保存的登录 session 也会清除。NAS 本身不受影响，之后可以重新添加。",
        post: `/api/profiles/${actEl.dataset.id}/delete`, target: "#roster",
        swap: "outerHTML", okLabel: "删除", toast: `已删除 ${actEl.dataset.id}。`,
      });
      return;
    }
    if (actEl && actEl.dataset.act === "token-delete") {
      showConfirmModal({
        kicker: "访问密钥", title: `删除 ${actEl.dataset.name}？`,
        body: "这把 key 会立即失效，使用它的 Agent 将无法再连接 MCP。",
        post: `/api/tokens/${actEl.dataset.id}/delete`, target: "#tokenRows",
        swap: "outerHTML", okLabel: "删除",
        toast: `已删除 ${actEl.dataset.name}。`,
      });
      return;
    }
    if (actEl && actEl.dataset.act === "token-copy") {
      copyTokenSecret(actEl, actEl.dataset.mode === "config" ? "config" : "key");
      return;
    }
    if (actEl && actEl.dataset.act === "token-rotate") {
      showConfirmModal({
        kicker: "访问密钥", title: `轮换 ${actEl.dataset.name}？`,
        body: "旧密钥会立即失效，正在使用它的 Agent 会马上断线，需要更新为新密钥。",
        post: `/api/tokens/${actEl.dataset.id}/rotate`, target: "#adminModalBody",
        swap: "innerHTML", okLabel: "轮换",
        toast: `已轮换 ${actEl.dataset.name}。`,
      });
      return;
    }
    const topoBtn = e.target.closest("#topologyBtn");
    if (topoBtn) {
      /* First click (data-loaded unset): htmx's own listener fetched the
         fragment and afterSwap set data-loaded. Later clicks arrive on
         the cloned button, which has no htmx listener — this is the only
         handler: pure visibility toggle, zero re-fetches. */
      const body = $("#topologyBody");
      if (body && body.dataset.loaded === "1") {
        const hide = !body.hidden;
        body.hidden = hide;
        topoBtn.textContent = hide ? "查看拓扑" : "隐藏拓扑";
        topoBtn.setAttribute("aria-expanded", hide ? "false" : "true");
        announce(hide ? "拓扑已隐藏。" : "拓扑已显示。");
      }
      return;
    }
    const closer = e.target.closest("[data-close]");
    if (closer) {
      if (closer.dataset.close === "login") hideLoginModal();
      if (closer.dataset.close === "confirm") hideConfirmModal();
      if (closer.dataset.close === "profile") hideProfileModal();
      if (closer.dataset.close === "admin") hideAdminModal();
      return;
    }
    if (e.target.closest("#drawerClose")) { closeDrawer(); return; }
    if (e.target.closest("#scrim")) { closeDrawer(); return; }
    const row = e.target.closest(".row");
    if (row && !e.target.closest("button, a")) {
      const btn = row.querySelector("[hx-get*='/drawer']");
      if (btn) btn.click();
    }
    const plain = e.target.closest("#tokenPlaintext");
    if (plain) { selectNode(plain); return; }
    const copyCfg = e.target.closest("#copyConfigBtn");
    if (copyCfg) {
      const endpoint = document.querySelector(".mcp-endpoint").textContent.trim();
      const cfg = JSON.stringify({ mcpServers: { fnos: { type: "http", url: endpoint, headers: { Authorization: "Bearer <token>" } } } }, null, 2);
      copyButton(copyCfg, cfg, {
        okMsg: "客户端配置已复制，请把 <token> 换成访问密钥。",
        failMsg: "复制失败，请手动复制地址并填入访问密钥。",
      });
      return;
    }
    const copyAuth = e.target.closest("#copyAuthBtn");
    if (copyAuth) {
      copyButton(copyAuth, copyAuth.dataset.url, {
        okMsg: "授权链接已复制。",
        failMsg: "复制失败，请手动选择链接。",
      });
      return;
    }
    const copyToken = e.target.closest("#copyTokenBtn");
    if (copyToken) {
      const code = $("#tokenPlaintext");
      const text = code ? code.textContent.trim() : "";
      if (!text) { toastAndAnnounce("没有可复制的密钥。", true); return; }
      copyButton(copyToken, text, {
        okMsg: "密钥已复制，可粘贴到客户端。",
        onFail: () => {
          if (code) { selectNode(code); code.focus(); }
          toastAndAnnounce("自动复制失败，已选中密钥，请按 Ctrl+C 或长按复制。", true);
        },
      });
      return;
    }
    const copyTokenConfig = e.target.closest("#copyTokenConfigBtn");
    if (copyTokenConfig) {
      const pre = $("#tokenClientConfig");
      const text = pre ? pre.textContent.trim() : "";
      if (!text) { toastAndAnnounce("没有可复制的客户端配置。", true); return; }
      copyButton(copyTokenConfig, text, {
        okMsg: "客户端配置已复制（含密钥），可直接粘贴。",
        onFail: () => {
          if (pre) {
            pre.hidden = false;
            pre.classList.add("token-config");
            pre.tabIndex = 0;
            selectNode(pre); pre.focus();
          }
          toastAndAnnounce("自动复制失败，已展开配置，请手动复制。", true);
        },
      });
      return;
    }
    const toCode = e.target.closest("#toCodeBtn");
    if (toCode) { $("#loginStep2").hidden = false; $("#codeInput").focus(); return; }
    const back = e.target.closest("#backToStep1");
    if (back) { $("#loginStep2").hidden = true; return; }
  });

  function wireLoginModal() {
    const input = $("#codeInput");
    const submit = $("#submitCodeBtn");
    if (input && submit) {
      input.addEventListener("input", () => {
        submit.disabled = !input.value.trim();
        const err = $("#loginError"); if (err) err.hidden = true;
      });
    }
  }

  const panelLogout = $("#panelLogoutBtn");
  if (panelLogout) panelLogout.addEventListener("click", async () => {
    await fetch("/api/panel/logout", {
      method: "POST", headers: { "X-CSRF-Token": csrf() },
    });
    location.href = "/login";
  });

  document.addEventListener("keydown", (e) => {
    if ((e.key === "Enter" || e.key === " ") &&
        document.activeElement && document.activeElement.id === "tokenPlaintext") {
      e.preventDefault();
      selectNode(document.activeElement);
      return;
    }
    if (e.key === "Escape") {
      const login = $("#loginModal"), confirm = $("#confirmModal"),
        profile = $("#profileModal"), admin = $("#adminModal"),
        drawer = $("#drawer");
      if (login && !login.hidden) hideLoginModal();
      else if (confirm && !confirm.hidden) hideConfirmModal();
      else if (profile && !profile.hidden) hideProfileModal();
      else if (admin && !admin.hidden) hideAdminModal();
      else if (drawer && drawer.classList.contains("on")) closeDrawer();
      return;
    }
    if (e.key !== "Tab") return;
    const login = $("#loginModal"), confirm = $("#confirmModal"),
      profile = $("#profileModal"), admin = $("#adminModal"),
      drawer = $("#drawer");
    if (login && !login.hidden) trapTab(login, e);
    else if (confirm && !confirm.hidden) trapTab(confirm, e);
    else if (profile && !profile.hidden) trapTab(profile, e);
    else if (admin && !admin.hidden) trapTab(admin, e);
    else if (drawer && drawer.classList.contains("on")) trapTab(drawer, e);
  });
})();

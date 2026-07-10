/* DDNS Manager — progressive enhancement layer.
   Everything works without JS (plain form POSTs); this adds modals, live
   dashboard polling, relative timestamps, filtering, and toasts.
   No inline handlers anywhere (CSP: default-src 'self'). */

(function () {
  "use strict";

  var csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";

  /* ------------------------------ toasts -------------------------------- */

  function toast(message, kind) {
    var region = document.getElementById("toasts");
    if (!region) return;
    var el = document.createElement("div");
    el.className = "toast toast-" + (kind || "info");
    el.setAttribute("role", "status");
    el.textContent = message;
    region.appendChild(el);
    dismissLater(el);
  }

  function dismissLater(el) {
    setTimeout(function () {
      el.classList.add("fade-out");
      setTimeout(function () { el.remove(); }, 450);
    }, 5000);
  }

  // Auto-dismiss server-rendered flash toasts.
  document.querySelectorAll("#toasts .toast").forEach(dismissLater);

  /* -------------------------- relative timestamps ------------------------ */

  function relTime(epoch) {
    if (!epoch) return "never";
    var diff = Math.floor(Date.now() / 1000 - epoch);
    if (diff < 5) return "just now";
    if (diff < 60) return diff + " s ago";
    if (diff < 3600) return Math.floor(diff / 60) + " min ago";
    if (diff < 86400) return Math.floor(diff / 3600) + " h ago";
    return Math.floor(diff / 86400) + " d ago";
  }

  function refreshTimestamps() {
    document.querySelectorAll("[data-ts]").forEach(function (el) {
      var ts = parseFloat(el.getAttribute("data-ts"));
      if (!isNaN(ts) && ts > 0) el.textContent = relTime(ts);
    });
  }
  refreshTimestamps();
  setInterval(refreshTimestamps, 15000);

  /* ------------------------- password reveal ----------------------------- */

  document.querySelectorAll(".reveal-toggle").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.getAttribute("data-reveal"));
      if (!input) return;
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.setAttribute("aria-label", show ? "Hide" : "Show");
    });
  });

  /* ------------------------------ modals --------------------------------- */

  var lastFocused = null;

  function openModal(id) {
    var backdrop = document.getElementById(id);
    if (!backdrop) return;
    lastFocused = document.activeElement;
    backdrop.hidden = false;
    var focusable = backdrop.querySelector("input, select, textarea, button");
    if (focusable) focusable.focus();
    document.body.style.overflow = "hidden";
  }

  function closeModals() {
    document.querySelectorAll(".modal-backdrop").forEach(function (b) { b.hidden = true; });
    document.body.style.overflow = "";
    if (lastFocused) lastFocused.focus();
  }

  document.addEventListener("click", function (e) {
    var opener = e.target.closest("[data-modal-open]");
    if (opener) {
      if (opener.id === "add-record-btn" || opener.getAttribute("data-modal-open") === "record-modal") {
        prepareRecordForm(null);
      }
      openModal(opener.getAttribute("data-modal-open"));
      return;
    }
    if (e.target.closest("[data-modal-close]")) { closeModals(); return; }
    if (e.target.classList && e.target.classList.contains("modal-backdrop")) closeModals();
  });

  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") closeModals();
  });

  /* ------------------------ record form (add/edit) ----------------------- */

  var recordForm = document.getElementById("record-form");
  var typeSelect = document.getElementById("rec-type");

  var CONTENT_META = {
    A:     { label: "IPv4 address", hint: "e.g. 203.0.113.7", placeholder: "203.0.113.7" },
    AAAA:  { label: "IPv6 address", hint: "e.g. 2001:db8::1", placeholder: "2001:db8::1" },
    CNAME: { label: "Target", hint: "The hostname this alias points to.", placeholder: "origin.example.com" },
    TXT:   { label: "Content", hint: "Text value (SPF, verification strings, …).", placeholder: "v=spf1 include:… ~all" },
    MX:    { label: "Mail server", hint: "Hostname of the mail server.", placeholder: "mail.example.com" }
  };

  function updateTypeFields() {
    if (!recordForm || !typeSelect) return;
    var type = typeSelect.value;
    recordForm.querySelectorAll("[data-types]").forEach(function (section) {
      var show = section.getAttribute("data-types").split(" ").indexOf(type) !== -1;
      section.hidden = !show;
      section.querySelectorAll("input, select, textarea").forEach(function (input) {
        input.disabled = !show;
      });
    });
    var meta = CONTENT_META[type];
    if (meta) {
      var label = document.getElementById("rec-content-label");
      var hint = document.getElementById("rec-content-hint");
      var content = document.getElementById("rec-content");
      if (label) label.textContent = meta.label;
      if (hint) hint.textContent = meta.hint;
      if (content) content.placeholder = meta.placeholder;
    }
    syncProxiedTtl();
  }

  function syncProxiedTtl() {
    var proxied = document.getElementById("rec-proxied");
    var ttl = document.getElementById("rec-ttl");
    if (!proxied || !ttl) return;
    if (!proxied.disabled && proxied.checked) {
      ttl.value = "1";
      ttl.disabled = true;
      ttl.title = "Proxied records always use Auto TTL";
    } else {
      ttl.disabled = false;
      ttl.title = "";
    }
  }

  if (typeSelect) {
    typeSelect.addEventListener("change", updateTypeFields);
    var proxiedBox = document.getElementById("rec-proxied");
    if (proxiedBox) proxiedBox.addEventListener("change", syncProxiedTtl);
    updateTypeFields();
  }

  function prepareRecordForm(record) {
    if (!recordForm) return;
    recordForm.reset();
    var title = document.getElementById("record-modal-title");
    var submitLabel = recordForm.querySelector("#record-submit .btn-label");

    if (!record) {
      recordForm.action = recordForm.getAttribute("data-create-action");
      if (title) title.textContent = "Add record";
      if (submitLabel) submitLabel.textContent = "Save record";
      typeSelect.disabled = false;
      updateTypeFields();
      return;
    }

    recordForm.action = "/records/" + record.id + "/update";
    if (title) title.textContent = "Edit " + record.type + " record";
    if (submitLabel) submitLabel.textContent = "Save changes";

    var known = ["A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA"];
    var isKnown = known.indexOf(record.type) !== -1;
    typeSelect.value = isKnown ? record.type : "OTHER";
    // Type changes on an existing record are rejected by Cloudflare's PUT —
    // lock the selector during edit.
    typeSelect.disabled = true;
    updateTypeFields();
    // A disabled select doesn't submit; mirror the type in a hidden input.
    ensureHidden(recordForm, "type", typeSelect.value);

    setValue("rec-name", record.name);
    setValue("rec-ttl", String(record.ttl || 1));
    var proxied = document.getElementById("rec-proxied");
    if (proxied) { proxied.checked = !!record.proxied; }

    if (isKnown && record.type !== "SRV" && record.type !== "CAA") {
      setValue("rec-content", record.content || "");
      if (record.type === "MX") setValue("rec-priority", String(record.priority || 10));
    } else if (record.type === "SRV" && record.data) {
      setValue("srv-priority", String(record.data.priority || 1));
      setValue("srv-weight", String(record.data.weight || 1));
      setValue("srv-port", String(record.data.port || ""));
      setValue("srv-target", record.data.target || "");
    } else if (record.type === "CAA" && record.data) {
      setValue("caa-flags", String(record.data.flags || 0));
      setValue("caa-tag", record.data.tag || "issue");
      setValue("caa-value", record.data.value || "");
    } else if (!isKnown) {
      setValue("other-type", record.type);
      setValue("other-json", JSON.stringify(
        record.data ? { data: record.data } : { content: record.content }, null, 2));
    }
    syncProxiedTtl();
  }

  function ensureHidden(form, name, value) {
    var input = form.querySelector('input[type="hidden"][name="' + name + '"]');
    if (!input) {
      input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      form.appendChild(input);
    }
    input.value = value;
  }

  function setValue(id, value) {
    var el = document.getElementById(id);
    if (el) el.value = value;
  }

  document.querySelectorAll(".edit-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var record;
      try { record = JSON.parse(btn.getAttribute("data-record")); }
      catch (e) { return; }
      prepareRecordForm(record);
      openModal("record-modal");
    });
  });

  if (recordForm) {
    recordForm.addEventListener("submit", function () {
      var btn = document.getElementById("record-submit");
      if (btn) {
        btn.disabled = true;
        var spin = btn.querySelector(".spinner");
        if (spin) spin.hidden = false;
      }
    });
  }

  /* --------------------------- delete confirm ---------------------------- */

  var pendingDeleteForm = null;

  document.querySelectorAll(".delete-form").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (form.dataset.confirmed === "1") return;
      e.preventDefault();
      pendingDeleteForm = form;
      var desc = document.getElementById("delete-desc");
      if (desc) desc.textContent = form.getAttribute("data-record-desc") || "this record";
      openModal("delete-modal");
    });
  });

  var confirmDeleteBtn = document.getElementById("confirm-delete-btn");
  if (confirmDeleteBtn) {
    confirmDeleteBtn.addEventListener("click", function () {
      if (!pendingDeleteForm) return;
      pendingDeleteForm.dataset.confirmed = "1";
      pendingDeleteForm.submit();
      closeModals();
    });
  }

  /* --------------------------- records filtering ------------------------- */

  var filterInput = document.getElementById("record-filter");
  var typeFilter = document.getElementById("type-filter");

  function applyFilter() {
    var q = (filterInput && filterInput.value || "").toLowerCase().trim();
    var type = typeFilter && typeFilter.value || "";
    var rows = document.querySelectorAll("#records-table tbody tr");
    var visible = 0;
    rows.forEach(function (row) {
      var matches =
        (!type || row.getAttribute("data-type") === type) &&
        (!q || row.getAttribute("data-name").indexOf(q) !== -1 ||
               row.getAttribute("data-content").indexOf(q) !== -1);
      row.hidden = !matches;
      if (matches) visible++;
    });
    var count = document.getElementById("record-count");
    if (count) count.textContent = visible + " record" + (visible === 1 ? "" : "s");
    var noMatches = document.getElementById("no-matches");
    if (noMatches) noMatches.hidden = visible !== 0 || rows.length === 0;
  }

  if (filterInput) filterInput.addEventListener("input", applyFilter);
  if (typeFilter) typeFilter.addEventListener("change", applyFilter);

  // Long TXT values: click to expand.
  document.querySelectorAll(".cell-content .truncate").forEach(function (el) {
    el.addEventListener("click", function () { el.classList.toggle("expanded"); });
  });

  /* -------------------------- dashboard polling -------------------------- */

  var statIpv4 = document.getElementById("stat-ipv4");

  function sessionExpired() {
    var banner = document.getElementById("session-expired");
    if (banner) banner.hidden = false;
  }

  function pollStatus() {
    fetch("/api/status", { headers: { "Accept": "application/json" } })
      .then(function (resp) {
        if (resp.status === 401) { sessionExpired(); throw new Error("auth"); }
        return resp.json();
      })
      .then(function (data) {
        setText("stat-ipv4", data.last_ipv4 || "—");
        setText("stat-ipv6", data.last_ipv6 || "not detected");
        setTs("stat-last-check", data.last_check_ts);
        setTs("stat-last-change", data.last_change_ts);
        setText("stat-interval", Math.round((data.poll_interval || 300) / 60));

        var ipAlert = data.alerts && data.alerts.ip_lookup;
        var dot = document.getElementById("status-dot");
        if (dot) dot.setAttribute("data-state",
          (data.cloudflare_error || ipAlert) ? "err" : "ok");

        var banner = document.getElementById("cf-error-banner");
        if (banner) {
          banner.hidden = !data.cloudflare_error;
          setText("cf-error-text", data.cloudflare_error || "");
        }
        var ipBanner = document.getElementById("ip-error-banner");
        if (ipBanner) {
          ipBanner.hidden = !ipAlert;
          setText("ip-error-text", ipAlert || "");
        }
        updateNotifyChip("notify-discord", data.notify && data.notify.discord);
        updateNotifyChip("notify-email", data.notify && data.notify.email);
      })
      .catch(function () { /* transient network errors: try again next tick */ });
  }

  function setText(id, value) {
    var el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  function setTs(id, ts) {
    var el = document.getElementById(id);
    if (!el) return;
    el.setAttribute("data-ts", ts || "");
    el.textContent = relTime(ts);
  }

  function updateNotifyChip(id, status) {
    var el = document.getElementById(id);
    if (!el) return;
    el.textContent = status || "nothing sent yet";
    el.classList.remove("chip-ok", "chip-err");
    if (status === "sent") el.classList.add("chip-ok");
    else if (status) el.classList.add("chip-err");
  }

  if (statIpv4) {
    setInterval(pollStatus, 10000);
  }

  /* ---------------------------- IP history -------------------------------- */

  var historyMoreBtn = document.getElementById("history-more-btn");

  // Absolute local time, same shape as the server-rendered rows.
  function absTime(epoch) {
    var d = new Date(epoch * 1000);
    function pad(n) { return (n < 10 ? "0" : "") + n; }
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) +
      " " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }

  function historyCell(className, text) {
    var td = document.createElement("td");
    if (className) td.className = className;
    td.textContent = text;
    return td;
  }

  function historyBadgeCell(className, text) {
    var td = document.createElement("td");
    var span = document.createElement("span");
    span.className = className;
    span.textContent = text;
    td.appendChild(span);
    return td;
  }

  function appendHistoryRows(entries) {
    var body = document.getElementById("history-body");
    if (!body) return;
    entries.forEach(function (h) {
      var tr = document.createElement("tr");
      tr.appendChild(historyBadgeCell(
        "badge badge-" + (h.family === "IPv4" ? "A" : "AAAA"), h.family));
      tr.appendChild(historyCell("mono", h.ip));
      tr.appendChild(historyCell("", absTime(h.started_ts)));
      tr.appendChild(h.ended_ts
        ? historyCell("", absTime(h.ended_ts))
        : historyBadgeCell("chip chip-ok", "active"));
      body.appendChild(tr);
    });
  }

  if (historyMoreBtn) {
    historyMoreBtn.addEventListener("click", function () {
      var spin = historyMoreBtn.querySelector(".spinner");
      historyMoreBtn.disabled = true;
      if (spin) spin.hidden = false;

      var before = historyMoreBtn.getAttribute("data-before") || "";
      var family = historyMoreBtn.getAttribute("data-family") || "";
      fetch("/api/ip-history?before=" + encodeURIComponent(before) +
            (family ? "&family=" + encodeURIComponent(family) : ""),
            { headers: { "Accept": "application/json" } })
        .then(function (resp) {
          if (resp.status === 401) { sessionExpired(); throw new Error("auth"); }
          if (!resp.ok) throw new Error("failed");
          return resp.json();
        })
        .then(function (data) {
          appendHistoryRows(data.entries || []);
          var last = (data.entries || [])[data.entries.length - 1];
          if (last) historyMoreBtn.setAttribute("data-before", String(last.id));
          historyMoreBtn.hidden = !data.has_more;
        })
        .catch(function (err) {
          if (err.message !== "auth") toast("Couldn't load more history. Try again.", "error");
        })
        .finally(function () {
          historyMoreBtn.disabled = false;
          if (spin) spin.hidden = true;
        });
    });
  }

  /* ----------------------------- check now -------------------------------- */

  var checkForm = document.getElementById("check-now-form");
  if (checkForm) {
    checkForm.addEventListener("submit", function (e) {
      e.preventDefault();
      var btn = document.getElementById("check-now-btn");
      var spin = btn && btn.querySelector(".spinner");
      if (btn) { btn.disabled = true; if (spin) spin.hidden = false; }

      fetch("/api/check-now", {
        method: "POST",
        headers: { "X-CSRFToken": csrfToken, "Accept": "application/json" }
      })
        .then(function (resp) {
          if (resp.status === 401 || resp.status === 400) { sessionExpired(); throw new Error("auth"); }
          if (!resp.ok) throw new Error("failed");
          toast("Check started — results will appear in a few seconds.", "success");
          setTimeout(pollStatus, 4000);
          setTimeout(pollStatus, 9000);
        })
        .catch(function (err) {
          if (err.message !== "auth") toast("Couldn't start the check. Try again.", "error");
        })
        .finally(function () {
          setTimeout(function () {
            if (btn) { btn.disabled = false; if (spin) spin.hidden = true; }
          }, 2000);
        });
    });
  }
})();

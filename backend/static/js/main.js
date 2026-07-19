// ── Custom alert modal ────────────────────────────────────────
(function () {
  const TYPES = {
    error:   { icon: 'bi-x-circle-fill',          title: 'Error'   },
    warning: { icon: 'bi-exclamation-triangle-fill', title: 'Warning' },
    success: { icon: 'bi-check-circle-fill',       title: 'Success' },
    info:    { icon: 'bi-info-circle-fill',         title: 'Info'    },
  };

  const overlay  = document.getElementById('clAlertOverlay');
  const box      = document.getElementById('clAlertBox');
  const stripe   = document.getElementById('clAlertStripe');
  const iconEl   = document.getElementById('clAlertIcon');
  const iconWrap = document.getElementById('clAlertIconWrap');
  const titleEl  = document.getElementById('clAlertTitle');
  const msgEl    = document.getElementById('clAlertMsg');
  const closeBtn = document.getElementById('clAlertClose');

  function close() {
    overlay.classList.remove('cl-alert-visible');
    overlay.removeAttribute('data-type');
  }

  closeBtn.addEventListener('click', close);
  overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && overlay.classList.contains('cl-alert-visible')) close();
  });

  window.showCLAlert = function (message, type, title) {
    type = TYPES[type] ? type : 'error';
    const cfg = TYPES[type];

    // Remove previous type classes
    box.className = 'cl-alert-box cl-alert-type-' + type;

    titleEl.textContent = title || cfg.title;
    msgEl.textContent   = message;

    iconEl.className = 'bi ' + cfg.icon;

    overlay.classList.add('cl-alert-visible');
    closeBtn.focus();
  };
})();

// ── Custom confirm modal ──────────────────────────────────────
(function () {
  const TYPES = {
    warning: { icon: 'bi-exclamation-triangle-fill', title: 'Confirm',      btn: '#f59e0b' },
    danger:  { icon: 'bi-x-octagon-fill',            title: 'Are you sure?', btn: '#ef4444' },
    info:    { icon: 'bi-info-circle-fill',           title: 'Confirm',      btn: '#3b82f6' },
  };

  const overlay   = document.getElementById('clConfirmOverlay');
  if (!overlay) return;                        // not on every page

  const box       = document.getElementById('clConfirmBox');
  const stripe    = document.getElementById('clConfirmStripe');
  const iconEl    = document.getElementById('clConfirmIcon');
  const iconWrap  = document.getElementById('clConfirmIconWrap');
  const titleEl   = document.getElementById('clConfirmTitle');
  const msgEl     = document.getElementById('clConfirmMsg');
  const cancelBtn = document.getElementById('clConfirmCancel');
  const okBtn     = document.getElementById('clConfirmOk');

  let _cb = null;

  function close() { overlay.classList.remove('cl-alert-visible'); _cb = null; }

  cancelBtn.addEventListener('click', close);
  overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && overlay.classList.contains('cl-alert-visible')) close();
  });

  okBtn.addEventListener('click', () => {
    const cb = _cb;
    close();
    if (cb) cb();
  });

  window.showCLConfirm = function (message, type, onConfirm) {
    type = TYPES[type] ? type : 'warning';
    const cfg = TYPES[type];

    box.className        = 'cl-alert-box cl-alert-type-' + type;
    stripe.style.background   = cfg.btn;
    iconEl.className     = 'bi ' + cfg.icon;
    iconWrap.style.color = cfg.btn;
    titleEl.textContent  = cfg.title;
    msgEl.textContent    = message;
    okBtn.style.background = cfg.btn;

    _cb = onConfirm;
    overlay.classList.add('cl-alert-visible');
    okBtn.focus();
  };
})();

// ── Toast notifications ───────────────────────────────────────
(function () {
  const TYPES = {
    success: { icon: 'bi-check-circle-fill',          title: 'Success' },
    error:   { icon: 'bi-x-circle-fill',              title: 'Error'   },
    warning: { icon: 'bi-exclamation-triangle-fill',  title: 'Warning' },
    info:    { icon: 'bi-info-circle-fill',            title: 'Info'    },
  };

  const stack = document.getElementById('clToastStack');

  window.showCLToast = function (message, type, duration) {
    type     = TYPES[type] ? type : 'info';
    duration = duration != null ? duration : 3500;
    const cfg = TYPES[type];

    const toast = document.createElement('div');
    toast.className = 'cl-toast cl-toast-' + type;
    toast.setAttribute('role', 'alert');
    toast.innerHTML =
      `<span class="cl-toast-icon"><i class="bi ${cfg.icon}"></i></span>` +
      `<div class="cl-toast-body">` +
        `<div class="cl-toast-title">${cfg.title}</div>` +
        `<div class="cl-toast-msg"></div>` +
      `</div>` +
      `<button class="cl-toast-close" aria-label="Dismiss"><i class="bi bi-x"></i></button>` +
      `<div class="cl-toast-progress"></div>`;

    toast.querySelector('.cl-toast-msg').textContent = message;
    stack.appendChild(toast);

    const progress = toast.querySelector('.cl-toast-progress');
    progress.style.width = '100%';
    requestAnimationFrame(() => {
      progress.style.transition = `width ${duration}ms linear`;
      progress.style.width = '0%';
    });

    function dismiss() {
      toast.classList.add('cl-toast-out');
      toast.addEventListener('animationend', () => toast.remove(), { once: true });
    }

    toast.querySelector('.cl-toast-close').addEventListener('click', dismiss);
    const timer = setTimeout(dismiss, duration);
    toast.addEventListener('mouseenter', () => clearTimeout(timer));
    toast.addEventListener('mouseleave', () => setTimeout(dismiss, 800));
  };
})();

// ── Live search (fetch, no full reload) ──────────────────────
// opts: { delay: ms debounce, minChars: only fire once the box has at
//         least this many chars — an empty box always fires (a reset) }
window.liveSearch = function (formId, resultIds, opts) {
  opts = opts || {};
  if (typeof opts === 'number') opts = { delay: opts };   // legacy signature
  var delay    = opts.delay    != null ? opts.delay    : 400;
  var minChars = opts.minChars != null ? opts.minChars : 0;
  var form = document.getElementById(formId);
  if (!form) return;
  if (typeof resultIds === 'string') resultIds = [resultIds];

  var timer;

  function run() {
    var params = new URLSearchParams(new FormData(form));
    var url = (form.getAttribute('action') || location.pathname) + '?' + params;

    resultIds.forEach(function (id) {
      var el = document.getElementById(id);
      if (el) { el.style.opacity = '0.35'; el.style.pointerEvents = 'none'; }
    });

    fetch(url)
      .then(function (r) { return r.text(); })
      .then(function (html) {
        var doc = new DOMParser().parseFromString(html, 'text/html');
        resultIds.forEach(function (id) {
          var fresh = doc.getElementById(id);
          var stale = document.getElementById(id);
          if (stale && fresh) stale.replaceWith(fresh);
          else if (stale) { stale.style.opacity = ''; stale.style.pointerEvents = ''; }
        });
        history.replaceState(null, '', url);
      })
      .catch(function () {
        resultIds.forEach(function (id) {
          var el = document.getElementById(id);
          if (el) { el.style.opacity = ''; el.style.pointerEvents = ''; }
        });
      });
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    clearTimeout(timer);
    run();
  });

  form.querySelectorAll('input[type="text"], input[type="search"], input:not([type])').forEach(function (el) {
    el.addEventListener('input', function () {
      clearTimeout(timer);
      var len = this.value.trim().length;
      // Fire when cleared (reset to default view) or past the threshold;
      // stay quiet for 1..minChars-1 characters.
      if (len === 0 || len >= minChars) {
        timer = setTimeout(run, delay);
      }
    });
  });

  form.querySelectorAll('select').forEach(function (el) {
    el.addEventListener('change', function () {
      clearTimeout(timer);
      timer = setTimeout(run, 0);
    });
  });
};

// Drag and drop for CSR upload
document.addEventListener('DOMContentLoaded', () => {
  const area = document.getElementById('uploadArea');
  if (!area) return;

  ['dragenter', 'dragover'].forEach(e => {
    area.addEventListener(e, ev => { ev.preventDefault(); area.classList.add('has-file'); });
  });
  ['dragleave', 'drop'].forEach(e => {
    area.addEventListener(e, ev => {
      ev.preventDefault();
      if (e === 'drop') {
        const file = ev.dataTransfer.files[0];
        if (file) {
          document.getElementById('csrFile').files = ev.dataTransfer.files;
          document.getElementById('fileName').textContent = file.name;
          document.getElementById('fileInfo').classList.remove('d-none');
        }
      } else {
        area.classList.remove('has-file');
      }
    });
  });
});

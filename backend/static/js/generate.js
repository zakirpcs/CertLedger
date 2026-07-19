(function () {
  'use strict';

  // ── SAN tag input ──────────────────────────────────────────────
  let sanList = [];

  const sanInputEl  = document.getElementById('sanInput');
  const sanTagsEl   = document.getElementById('sanTags');
  const sanHiddenEl = document.getElementById('sanHidden');

  function normalizeSan(raw) {
    raw = raw.trim().replace(/^,+|,+$/g, '');
    if (!raw) return null;
    if (raw.startsWith('DNS:') || raw.startsWith('IP:')) return raw;
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(raw) ? 'IP:' + raw : 'DNS:' + raw;
  }

  function addSan(raw) {
    const val = normalizeSan(raw);
    if (!val || sanList.includes(val)) { sanInputEl.value = ''; return; }
    sanList.push(val);
    renderSanTags();
    sanInputEl.value = '';
  }

  function removeSan(i) { sanList.splice(i, 1); renderSanTags(); }
  window.removeSan = removeSan;

  function renderSanTags() {
    sanTagsEl.innerHTML = sanList.map((s, i) => {
      const type = s.startsWith('IP:') ? 'IP' : 'DNS';
      const val  = s.replace(/^(DNS|IP):/, '');
      return `<span class="san-chip"><span class="san-type">${type}</span><span class="san-val">${val}</span><button type="button" onclick="removeSan(${i})" aria-label="Remove">&times;</button></span>`;
    }).join('');
    sanHiddenEl.value = JSON.stringify(sanList);
  }

  sanInputEl.addEventListener('keydown', e => {
    if (['Enter', ',', 'Tab'].includes(e.key)) { e.preventDefault(); addSan(sanInputEl.value); }
    if (e.key === 'Backspace' && !sanInputEl.value && sanList.length) { removeSan(sanList.length - 1); }
  });
  sanInputEl.addEventListener('blur', () => { if (sanInputEl.value.trim()) addSan(sanInputEl.value); });
  sanInputEl.addEventListener('paste', e => {
    e.preventDefault();
    (e.clipboardData || window.clipboardData).getData('text').split(/[\n,\s]+/).forEach(addSan);
  });

  // ── Key generation ─────────────────────────────────────────────
  // Strategy: Web Crypto API (preferred, requires HTTPS / localhost)
  //           → forge synchronous fallback (works over plain HTTP)

  const hasWebCrypto = !!(window.crypto && window.crypto.subtle);

  if (!hasWebCrypto) {
    const note = document.getElementById('httpCryptoNote');
    if (note) note.style.display = '';
  }

  // Web Crypto path ─────────────────────────────────────────────
  function b64urlToBytes(b64url) {
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(b64);
    const buf = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
    return buf;
  }

  function jwkParamToBigInt(b64url) {
    const hex = Array.from(b64urlToBytes(b64url))
                     .map(b => b.toString(16).padStart(2, '0')).join('');
    return new forge.jsbn.BigInteger(hex, 16);
  }

  async function generateViaWebCrypto(bits) {
    const pair = await window.crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: bits,
        publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true, ['sign', 'verify']
    );
    const jwk = await window.crypto.subtle.exportKey('jwk', pair.privateKey);
    const n  = jwkParamToBigInt(jwk.n),  e  = jwkParamToBigInt(jwk.e);
    const d  = jwkParamToBigInt(jwk.d),  p  = jwkParamToBigInt(jwk.p);
    const q  = jwkParamToBigInt(jwk.q),  dp = jwkParamToBigInt(jwk.dp);
    const dq = jwkParamToBigInt(jwk.dq), qi = jwkParamToBigInt(jwk.qi);
    return {
      privateKey: forge.pki.rsa.setPrivateKey(n, e, d, p, q, dp, dq, qi),
      publicKey:  forge.pki.rsa.setPublicKey(n, e),
    };
  }

  // Forge synchronous fallback (HTTP-safe, workers: 0 = no worker file) ─
  function generateViaForge(bits) {
    return new Promise((resolve, reject) => {
      // setTimeout lets the browser render the loading state
      // before the synchronous prime generation blocks the thread.
      setTimeout(() => {
        try {
          resolve(forge.pki.rsa.generateKeyPair({ bits, workers: 0 }));
        } catch (e) { reject(e); }
      }, 60);
    });
  }

  async function generateKeyPair(bits, statusEl) {
    if (hasWebCrypto) {
      return generateViaWebCrypto(bits);
    }
    // Over plain HTTP: warn the user and use forge (may freeze ~1–5 s for 2048, longer for 4096)
    if (statusEl) statusEl.textContent = `Generating ${bits}-bit key (this may take a few seconds)…`;
    return generateViaForge(bits);
  }

  // ── CSR construction (forge only, no key gen) ──────────────────
  function buildCSR(keypair, subject, sans) {
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = keypair.publicKey;

    const attrs = [];
    if (subject.cn)      attrs.push({ name: 'commonName',             value: subject.cn });
    if (subject.org)     attrs.push({ name: 'organizationName',       value: subject.org });
    if (subject.ou)      attrs.push({ name: 'organizationalUnitName', value: subject.ou });
    if (subject.country) attrs.push({ name: 'countryName',            value: subject.country.slice(0,2).toUpperCase() });
    if (subject.state)   attrs.push({ name: 'stateOrProvinceName',    value: subject.state });
    if (subject.city)    attrs.push({ name: 'localityName',           value: subject.city });
    if (subject.email)   attrs.push({ name: 'emailAddress',           value: subject.email });
    csr.setSubject(attrs);

    if (sans.length) {
      csr.setAttributes([{
        name: 'extensionRequest',
        extensions: [{
          name: 'subjectAltName',
          altNames: sans.map(s => s.startsWith('IP:')
            ? { type: 7, ip: s.slice(3) }
            : { type: 2, value: s.replace(/^DNS:/, '') })
        }]
      }]);
    }

    csr.sign(keypair.privateKey, forge.md.sha256.create());
    return csr;
  }

  function slugify(s) { return s.replace(/[^a-zA-Z0-9._-]/g, '_').replace(/_+/g, '_'); }

  function makeDownload(id, content, filename) {
    const el = document.getElementById(id);
    if (el._objectUrl) URL.revokeObjectURL(el._objectUrl);
    const url = URL.createObjectURL(new Blob([content], { type: 'application/x-pem-file' }));
    el._objectUrl = url;
    el.href = url;
    el.download = filename;
  }

  // ── Generate button ────────────────────────────────────────────
  const generateBtn       = document.getElementById('generateBtn');
  const outputPlaceholder = document.getElementById('outputPlaceholder');
  const cnInput           = document.getElementById('cn');

  generateBtn.addEventListener('click', async () => {
    if (!cnInput.value.trim()) { cnInput.focus(); cnInput.reportValidity(); return; }

    const cn      = cnInput.value.trim();
    const keySize = parseInt(document.querySelector('input[name="keySize"]:checked').value);
    const sans    = sanList.slice();
    if (!sans.length && /[.\-]/.test(cn)) sans.push('DNS:' + cn);

    const subject = {
      cn,
      org:     document.getElementById('org').value.trim(),
      ou:      document.getElementById('ou').value.trim(),
      country: document.getElementById('country').value.trim(),
      state:   document.getElementById('state').value.trim(),
      city:    document.getElementById('city').value.trim(),
      email:   document.getElementById('email').value.trim(),
    };

    generateBtn.disabled = true;
    generateBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-2" role="status"></span>Generating ${keySize}-bit key…`;
    outputPlaceholder.style.display = 'none';
    document.getElementById('outputContent').style.display = 'none';

    try {
      const keypair    = await generateKeyPair(keySize, generateBtn);
      const csr        = buildCSR(keypair, subject, sans);
      const privKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
      const csrPem     = forge.pki.certificationRequestToPem(csr);
      const slug       = slugify(cn);

      document.getElementById('outPrivKey').value         = privKeyPem;
      document.getElementById('outCSR').value             = csrPem;
      document.getElementById('outCN').textContent        = cn;
      document.getElementById('submitCsrHidden').value    = csrPem;

      if (sans.length) {
        document.getElementById('outSans').innerHTML = sans.map(s =>
          `<span class="san-chip-sm">${s}</span>`).join('');
        document.getElementById('sanPreviewRow').style.display = '';
      } else {
        document.getElementById('sanPreviewRow').style.display = 'none';
      }

      makeDownload('dlPrivKey', privKeyPem, slug + '.key');
      makeDownload('dlCSR',     csrPem,     slug + '.csr');

      document.getElementById('outputContent').style.display  = '';
      document.getElementById('submitSection').style.display  = '';
      document.getElementById('submitSuccess').style.display  = 'none';
      document.getElementById('submitToCA').style.display     = '';
      document.getElementById('outputPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });

    } catch (err) {
      outputPlaceholder.style.display = '';
      console.error(err);
      showCLAlert('Generation failed: ' + (err.message || err), 'error');
    } finally {
      generateBtn.disabled = false;
      generateBtn.innerHTML = '<i class="bi bi-arrow-repeat me-2"></i>Regenerate';
    }
  });

  // ── Copy helper ────────────────────────────────────────────────
  window.copyField = function (id, btn) {
    const label = id === 'outPrivKey' ? 'Private key' : 'CSR';
    navigator.clipboard.writeText(document.getElementById(id).value).then(() => {
      const orig = btn.innerHTML;
      btn.innerHTML = '<i class="bi bi-check"></i>';
      setTimeout(() => btn.innerHTML = orig, 1600);
      showCLToast(label + ' copied to clipboard.', 'success', 2500);
    }).catch(() => {
      showCLToast('Copy failed — please select and copy manually.', 'warning');
    });
  };

  // ── Inline submit to CA ────────────────────────────────────────
  document.getElementById('submitToCA').addEventListener('submit', async e => {
    e.preventDefault();
    const csrPem = document.getElementById('submitCsrHidden').value;
    if (!csrPem) return;

    const cn  = document.getElementById('outCN').textContent;
    const fd  = new FormData(e.target);
    fd.append('csr_file', new Blob([csrPem], { type: 'application/x-pem-file' }), slugify(cn) + '.csr');

    const btn = e.target.querySelector('button[type=submit]');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Submitting…';

    try {
      const resp = await fetch('/submit', {
        method: 'POST',
        body: fd,
        headers: { 'Accept': 'application/json' },
      });
      const data = await resp.json();

      if (resp.ok && data.tracking_id) {
        showCLToast('CSR submitted — awaiting CA review.', 'success', 4000);
        e.target.style.display = 'none';
        const s = document.getElementById('submitSuccess');
        s.innerHTML = `
          <div class="alert alert-success border-0 mb-0">
            <h6 class="fw-bold mb-2"><i class="bi bi-check-circle-fill me-2"></i>Submitted!</h6>
            <p class="mb-1 small">CSR for <strong>${data.common_name}</strong> is pending review.</p>
            <p class="mb-3 small">Tracking ID: <code class="user-select-all">${data.tracking_id}</code></p>
            <a href="/status?id=${data.tracking_id}" class="btn btn-sm btn-success">
              <i class="bi bi-search me-1"></i>Check Status
            </a>
          </div>`;
        s.style.display = '';
      } else {
        showCLAlert(data.error || 'Submission failed. Please try again.', 'error');
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-send me-2"></i>Submit to CA';
      }
    } catch (err) {
      showCLAlert('Submission failed: ' + err.message, 'error');
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-send me-2"></i>Submit to CA';
    }
  });

})();

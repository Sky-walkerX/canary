// Canary's browser evidence checker. No framework, no outside requests.
//
// It loads canary.wasm, the Go build of cmd/verify-wasm, and checks evidence
// files with the same code canary verify runs. The report it shows is the
// markup the dashboard renders, made by the module from the shared wording
// table, so the site, the dashboard and the CLI use the same words.
//
// It mounts into the element with id "checker" and wires these hooks there,
// creating any the page lacks:
//   [data-checker-file]     the file input. A file or text dropped anywhere on
//                           the checker works too.
//   [data-checker-try]      buttons that check the files named by the
//                           checker's data-evidence ("real") and data-tampered
//                           ("tampered") attributes.
//   [data-checker-result]   where the report goes.
//   [data-checker-pending]  the line that says the checker is loading, failed
//                           to load, or can't run in this browser.
//   [data-checker-live]     sentences that say the check runs in this page.
//                           They stay hidden until it can.
//   [data-checker-build]    the line that names the commit and Go release
//                           the module was built from.
//   script[type="application/json"][data-checker-text]
//                           the words to show, keyed as in TEXT. The site
//                           generator writes them from the wording table.
// It reads these attributes on the checker element:
//   data-wasm       the module's address. The default is canary.wasm beside
//                   this script.
//   data-wasm-exec  Go's wasm_exec.js. The default is wasm_exec.js beside this
//                   script.
//   data-wasm-size  optional: the module's size in bytes once decoded, which
//                   drives the progress bar.
//   data-wasm-build optional: the build line, as the site generator read it
//                   from the module file. Without it, the line comes from
//                   the module's own report once it loads.
// The defaults suit a site that ships the module, wasm_exec.js and this
// script in one folder named by a hash of all three. A browser can then keep
// them for good, and never pairs this script with a module from another
// build.
//
// Network use. Once the page has loaded, it fetches wasm_exec.js, the module
// and the two sample files, all from this origin. Once the checker is ready
// it makes no request at all. A file the reader picks, drops or pastes is read inside the
// page and handed to the module. It is never uploaded.
(() => {
  'use strict';

  // Fallback words, for a page that carries no [data-checker-text] block. The
  // block replaces each of them. A Go test in internal/ui holds these to the
  // wording table word for word, so they never drift from what the site
  // writes. The two "Can't read this file" lines are replaced again by the
  // module once it loads, so they match canary verify word for word.
  const TEXT = {
    loadingStart: 'Loading the checker.',
    loading: 'Loading the checker, a {size} download.',
    starting: 'Starting the checker.',
    failed: "The checker failed to load, so this page can't check files. " +
      'Try again, or download the file and run this in a terminal:',
    noWasm: "This browser can't run WebAssembly, so the checker can't run in this page. " +
      'Download the file and run this in a terminal:',
    retry: 'Try loading again',
    choose: 'Choose an evidence file',
    details: 'Technical details',
    command: 'canary verify FILE',
    checking: 'Checking the file in this browser.',
    internal: 'The checker stopped with an internal error and did not check this file. ' +
      'Run this in a terminal instead:',
    source: 'File: {name}',
    sourcePaste: 'Pasted text',
    sourceDrop: 'Dropped text',
    pasteOpen: "Paste the file's text instead",
    pasteLabel: 'Text of an evidence file',
    pasteButton: 'Check the pasted text',
    pasteEmpty: 'Paste the text of an evidence file first.',
    build: 'Built from commit {revision} with {go}.',
    buildModified: 'Built from commit {revision} plus uncommitted changes, with {go}.',
    buildNoRevision: 'Built with {go}.',
    tooLarge: "Can't read this file: it is larger than 16 MiB, far more than any block's evidence.",
    notOpened: "Can't read this file: the system would not let Canary open it.",
  };

  // The module enforces nothing about size; this limit matches canary verify
  // and the dashboard, and the module reports its own once it loads.
  const DEFAULT_MAX_BYTES = 16 << 20;

  // The script's own address, read now: document.currentScript is gone once
  // this first run ends.
  const scriptSrc = document.currentScript ? document.currentScript.src : '';

  function fill(s, vars) {
    return s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
  }

  function wasmSupported() {
    return typeof WebAssembly === 'object' && typeof WebAssembly.instantiate === 'function';
  }

  function megabytes(n) {
    return Math.max(0.1, n / 1e6).toFixed(1) + ' MB';
  }

  function el(tag, attrs, textContent) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
    if (textContent !== undefined) e.textContent = textContent;
    return e;
  }

  // icon returns a sprite icon. The markup is fixed; nothing in it comes from
  // a file or the network.
  function icon(name) {
    const t = document.createElement('template');
    t.innerHTML = '<svg class="icon" aria-hidden="true" focusable="false"><use href="#i-' + name + '"></use></svg>';
    return t.content.firstChild;
  }

  // sameOrigin resolves url against the page and refuses another origin, so
  // a changed attribute can't point the checker anywhere else.
  function sameOrigin(url) {
    const u = new URL(url, document.baseURI);
    if (u.origin !== location.origin) throw new Error('checker: ' + url + ' is not on this site');
    return u.href;
  }

  // beside resolves a file name against this script's own address, or the
  // page's when the script's address is unknown.
  function beside(name) {
    return new URL(name, scriptSrc || document.baseURI).href;
  }

  function baseName(url) {
    try {
      const p = new URL(url, document.baseURI).pathname;
      return decodeURIComponent(p.slice(p.lastIndexOf('/') + 1)) || url;
    } catch (e) {
      return url;
    }
  }

  // setHidden hides or shows an element. A page rule such as display: flex
  // beats the hidden attribute alone, so the inline display goes with it.
  // Setting a style property from script is not an inline style under CSP.
  function setHidden(e, hide) {
    e.hidden = hide;
    e.style.display = hide ? 'none' : '';
  }

  function readTextOverrides(root) {
    const block = root.querySelector('script[type="application/json"][data-checker-text]');
    if (!block) return {};
    try {
      const v = JSON.parse(block.textContent);
      const out = {};
      for (const k of Object.keys(TEXT)) if (typeof v[k] === 'string' && v[k] !== '') out[k] = v[k];
      return out;
    } catch (e) {
      return {};
    }
  }

  // linkStyles adds checker.css, which sits beside this script, unless the
  // page already links it.
  function linkStyles() {
    if (!scriptSrc || document.querySelector('link[data-checker-css], link[href$="checker/checker.css"]')) return;
    const href = new URL('checker.css', scriptSrc);
    if (href.origin !== location.origin) return;
    document.head.appendChild(el('link', { rel: 'stylesheet', href: href.href, 'data-checker-css': '' }));
  }

  function loadGo(src) {
    if (typeof globalThis.Go === 'function') return Promise.resolve(globalThis.Go);
    return new Promise((resolve, reject) => {
      const s = el('script', { src: sameOrigin(src) });
      s.onload = () => {
        if (typeof globalThis.Go === 'function') resolve(globalThis.Go);
        else reject(new Error('checker: ' + src + ' loaded but did not define Go'));
      };
      s.onerror = () => {
        s.remove();
        reject(new Error('checker: ' + src + ' did not load'));
      };
      document.head.appendChild(s);
    });
  }

  async function fetchOK(url) {
    const r = await fetch(sameOrigin(url), { mode: 'same-origin', credentials: 'same-origin' });
    if (!r.ok) throw new Error('checker: ' + url + ': HTTP ' + r.status);
    return r;
  }

  // counted wraps a response so each chunk read reports the running total of
  // decoded bytes, and the end of the stream reports it once more with end
  // set. Without stream support it returns the response unchanged.
  function counted(resp, onBytes) {
    if (!resp.body || typeof ReadableStream !== 'function') return resp;
    const reader = resp.body.getReader();
    let done = 0;
    const stream = new ReadableStream({
      async pull(ctrl) {
        const r = await reader.read();
        if (r.done) {
          onBytes(done, true);
          ctrl.close();
          return;
        }
        done += r.value.byteLength;
        onBytes(done, false);
        ctrl.enqueue(r.value);
      },
      cancel(reason) {
        return reader.cancel(reason);
      },
    });
    return new Response(stream, { status: resp.status, statusText: resp.statusText, headers: resp.headers });
  }

  // preloadFonts fetches the monospace face while the checker loads. A report
  // sets hashes in it, and a page that has shown none yet would otherwise
  // fetch the font after the checker is ready.
  function preloadFonts() {
    if (!document.fonts || typeof document.fonts.load !== 'function') return Promise.resolve();
    const mono = getComputedStyle(document.documentElement).getPropertyValue('--font-mono').trim();
    if (!mono) return Promise.resolve();
    return document.fonts.load('1em ' + mono).catch(() => {});
  }

  function readFile(file) {
    if (typeof file.arrayBuffer === 'function') return file.arrayBuffer();
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = () => reject(r.error || new Error('checker: the browser could not read the file'));
      r.readAsArrayBuffer(file);
    });
  }

  function mount(root) {
    const text = Object.assign({}, TEXT, readTextOverrides(root));
    const cfg = {
      wasm: root.getAttribute('data-wasm') || beside('canary.wasm'),
      exec: root.getAttribute('data-wasm-exec') || beside('wasm_exec.js'),
      size: parseInt(root.getAttribute('data-wasm-size') || '', 10) || 0,
      build: root.getAttribute('data-wasm-build') || '',
      samples: { real: root.getAttribute('data-evidence'), tampered: root.getAttribute('data-tampered') },
    };

    // The hooks, made when the page lacks them.
    let result = root.querySelector('[data-checker-result]');
    if (!result) {
      result = el('div', { class: 'checker-result', 'data-checker-result': '' });
      root.appendChild(result);
    }
    let pending = root.querySelector('[data-checker-pending]');
    if (!pending) {
      pending = el('p', { class: 'checker-pending', 'data-checker-pending': '' });
      pending.append(icon('info'), el('span'));
      result.prepend(pending);
    }
    const pendingText = pending.querySelector(':scope > span') || pending;
    let input = root.querySelector('[data-checker-file]');
    if (!input) {
      const drop = el('label', { class: 'drop' });
      input = el('input', { class: 'drop-input', type: 'file', accept: '.json,application/json', 'data-checker-file': '' });
      drop.append(el('span', { class: 'drop-label' }, text.choose), input);
      root.insertBefore(drop, result);
    }
    let build = root.querySelector('[data-checker-build]');
    if (!build) {
      build = el('p', { class: 'checker-build', 'data-checker-build': '' });
      setHidden(build, true);
      root.appendChild(build);
    }
    input.disabled = true;
    const tries = Array.from(root.querySelectorAll('[data-checker-try]'));
    tries.forEach((b) => { b.disabled = true; });

    // Loading, failure and no-WebAssembly details go under the pending line,
    // which is a paragraph and can't hold them.
    const extra = el('div', { class: 'checker-extra', 'data-checker-extra': '' });
    pending.after(extra);

    // The whole report would be read aloud if the result area stayed a live
    // region. One short status line is announced instead.
    result.setAttribute('aria-live', 'off');
    const status = el('p', { class: 'sr-only', role: 'status', 'data-checker-status': '' });
    result.appendChild(status);

    let ready = false;
    let loading = false;
    let maxBytes = DEFAULT_MAX_BYTES;
    let samples = {};
    let queued = null;
    let seq = 0;
    let shown = null;

    function setPending(s) {
      setHidden(pending, false);
      pendingText.textContent = s;
    }

    function command() {
      const box = el('div', { class: 'command' });
      const pre = el('pre');
      pre.appendChild(el('code', {}, text.command));
      box.appendChild(pre);
      return box;
    }

    function technical(err) {
      const d = el('details', { class: 'tech' });
      const s = el('summary');
      s.append(icon('chevron'), el('span', {}, text.details));
      const pre = el('pre');
      pre.appendChild(el('code', {}, String((err && err.message) || err)));
      d.append(s, pre);
      return d;
    }

    function fail(err) {
      ready = false;
      loading = false;
      queued = null;
      extra.replaceChildren();
      setPending(text.failed);
      const retry = el('button', { type: 'button', class: 'btn' }, text.retry);
      retry.addEventListener('click', () => load());
      extra.append(command(), retry, technical(err));
      if (typeof console !== 'undefined') console.error(err);
    }

    async function load() {
      if (loading || ready) return;
      extra.replaceChildren();
      if (!wasmSupported()) {
        setPending(text.noWasm);
        extra.append(command());
        return;
      }
      loading = true;
      setPending(text.loadingStart);
      const bar = el('progress', { class: 'checker-progress', 'aria-label': text.loadingStart });
      extra.append(bar);

      try {
        const samplesP = loadSamples();
        const fontsP = preloadFonts();
        const [resp, Go] = await Promise.all([fetchOK(cfg.wasm), loadGo(cfg.exec)]);
        // Two sizes, kept apart. The sentence names the download: the
        // Content-Length, which counts the bytes on the wire, compressed or
        // not. The bar counts decoded bytes, which is what the stream yields,
        // against the module's own size. A compressed body's Content-Length
        // measures something else, so it never drives the bar.
        const encoding = (resp.headers.get('Content-Encoding') || 'identity').trim().toLowerCase();
        const length = parseInt(resp.headers.get('Content-Length') || '', 10) || 0;
        const total = cfg.size || (encoding === 'identity' ? length : 0);
        if (length) setPending(fill(text.loading, { size: megabytes(length) }));
        if (total) bar.max = total;
        let last = 0;
        const progress = (done, end) => {
          const now = Date.now();
          if (!end && now - last < 100) return;
          last = now;
          if (total) bar.value = end ? total : Math.min(done, total);
          if (end) setPending(text.starting);
        };

        const go = new Go();
        const type = (resp.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
        const body = counted(resp, progress);
        let module;
        if (type === 'application/wasm' && typeof WebAssembly.instantiateStreaming === 'function') {
          module = await WebAssembly.instantiateStreaming(body, go.importObject);
        } else {
          // Streaming refuses a module served under another MIME type, so
          // read it whole instead.
          module = await WebAssembly.instantiate(await body.arrayBuffer(), go.importObject);
        }
        // run executes main up to its select {}, which sets the functions,
        // before it returns. Its promise settles only if the program exits.
        go.run(module.instance).catch((err) => console.error(err));
        if (typeof globalThis.canaryVerify !== 'function') {
          throw new Error('checker: the module did not set canaryVerify');
        }
        const info = JSON.parse(globalThis.canaryCheckerInfo());
        if (info.max_file_bytes > 0) maxBytes = info.max_file_bytes;
        if (info.too_large) text.tooLarge = info.too_large;
        if (info.not_opened) text.notOpened = info.not_opened;
        samples = await samplesP;
        await fontsP;
        becomeReady(info);
      } catch (err) {
        fail(err);
      }
    }

    // loadSamples fetches the two example files while the module loads, so
    // the buttons that check them need no request later. A sample that fails
    // to load leaves its button disabled; its download link still works.
    async function loadSamples() {
      const out = {};
      await Promise.all(Object.keys(cfg.samples).map(async (key) => {
        const url = cfg.samples[key];
        if (!url) return;
        try {
          const r = await fetchOK(url);
          out[key] = { name: baseName(url), bytes: new Uint8Array(await r.arrayBuffer()) };
        } catch (err) {
          console.error(err);
        }
      }));
      return out;
    }

    function becomeReady(info) {
      ready = true;
      loading = false;
      extra.replaceChildren();
      setHidden(pending, true);
      input.disabled = false;
      tries.forEach((b) => { b.disabled = !samples[b.getAttribute('data-checker-try')]; });
      root.querySelectorAll('[data-checker-live]').forEach((e) => setHidden(e, false));
      // The page's line wins: the site generator read it from the very file
      // this page loaded. The module's own report fills in for a page
      // without one.
      const go = info.go_release || info.go_version;
      let line = cfg.build;
      if (!line && go) {
        const vars = { go, revision: (info.revision || '').slice(0, 7) };
        line = fill(!vars.revision ? text.buildNoRevision : info.modified ? text.buildModified : text.build, vars);
      }
      if (line) {
        build.textContent = line;
        setHidden(build, false);
      }
      addPaste();
      if (queued) {
        const run = queued;
        queued = null;
        run();
      }
    }

    // when runs fn now if the checker is ready, or once it is.
    function when(fn) {
      if (ready) fn();
      else if (loading) queued = fn;
    }

    // show replaces the last result. The page's notes about the eight steps
    // give way to the first report.
    function show(node, announce) {
      if (!shown) {
        for (const c of Array.from(result.children)) {
          if (c !== status) setHidden(c, true);
        }
      }
      if (shown) shown.remove();
      shown = node;
      result.insertBefore(node, status);
      status.textContent = announce;
      reveal(node);
    }

    // reveal scrolls a new report to the top of the screen when it starts
    // above it or in its lower part. On a narrow screen the report sits below
    // the buttons, so a tap would otherwise change little the reader can see.
    function reveal(node) {
      const top = node.getBoundingClientRect().top;
      if (top >= 0 && top < window.innerHeight * 0.6) return;
      const still = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      node.scrollIntoView({ block: 'start', behavior: still ? 'auto' : 'smooth' });
    }

    function wrap(source) {
      const w = el('div', { class: 'checker-report', 'data-checker-report': '' });
      w.appendChild(el('p', { class: 'checker-source' }, source));
      return w;
    }

    function showMessage(source, message, err, withCommand) {
      const w = wrap(source);
      const r = el('div', { class: 'report' });
      r.appendChild(el('p', { class: 'report-message' }, message));
      if (withCommand) r.appendChild(command());
      if (err) r.appendChild(technical(err));
      w.appendChild(r);
      show(w, message);
    }

    function check(bytes, source) {
      const mine = ++seq;
      if (bytes.length > maxBytes) {
        showMessage(source, text.tooLarge);
        return;
      }
      status.textContent = text.checking;
      let out;
      try {
        out = JSON.parse(globalThis.canaryVerify(bytes));
      } catch (err) {
        if (mine === seq) showMessage(source, text.internal, err, true);
        return;
      }
      if (mine !== seq) return;
      // A report without markup means the module broke, not the file. The
      // reader gets the internal-error state and the command, never a second
      // rendering in other words.
      if (!out || typeof out.result !== 'string' || typeof out.html !== 'string' || !out.html) {
        showMessage(source, text.internal, new Error((out && out.error) || 'checker: the module returned no report markup'), true);
        return;
      }
      // The module escapes every value that came from the file, as Go's
      // html/template does. A Go test holds this markup to the dashboard's
      // template, byte for byte.
      const w = wrap(source);
      const body = el('div');
      body.innerHTML = out.html;
      w.append(...body.childNodes);
      show(w, out.headline || out.message || '');
    }

    async function checkFile(file) {
      const mine = ++seq;
      const source = fill(text.source, { name: file.name || '' });
      if (file.size > maxBytes) {
        showMessage(source, text.tooLarge);
        return;
      }
      let bytes;
      try {
        bytes = new Uint8Array(await readFile(file));
      } catch (err) {
        if (mine === seq) showMessage(source, text.notOpened, err);
        return;
      }
      if (mine === seq) check(bytes, source);
    }

    function checkText(s, source) {
      check(new TextEncoder().encode(s), source);
    }

    input.addEventListener('change', () => {
      const file = input.files && input.files[0];
      if (file) when(() => checkFile(file));
      // Clear it, so choosing the same file again checks it again.
      input.value = '';
    });

    tries.forEach((b) => {
      b.addEventListener('click', () => {
        const s = samples[b.getAttribute('data-checker-try')];
        if (s) check(s.bytes, fill(text.source, { name: s.name }));
      });
    });

    // Drops land on the whole checker. Handling them here, never as the file
    // input's default, keeps one path for files and text alike.
    let depth = 0;
    const carries = (e) => e.dataTransfer && Array.from(e.dataTransfer.types || []).some((t) => t === 'Files' || t === 'text/plain');
    root.addEventListener('dragenter', (e) => {
      if (!carries(e)) return;
      e.preventDefault();
      depth++;
      root.setAttribute('data-dragover', '');
    });
    root.addEventListener('dragover', (e) => {
      if (!carries(e)) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = 'copy';
    });
    root.addEventListener('dragleave', () => {
      depth = Math.max(0, depth - 1);
      if (depth === 0) root.removeAttribute('data-dragover');
    });
    root.addEventListener('drop', (e) => {
      if (!carries(e)) return;
      e.preventDefault();
      depth = 0;
      root.removeAttribute('data-dragover');
      const file = e.dataTransfer.files && e.dataTransfer.files[0];
      if (file) {
        when(() => checkFile(file));
        return;
      }
      const s = e.dataTransfer.getData('text/plain');
      if (s) when(() => checkText(s, text.sourceDrop));
    });

    // A paste while the checker has focus checks the pasted file or text. So
    // does pasting text that looks like JSON while nothing has focus. A paste
    // into any other field on the page is left alone.
    document.addEventListener('paste', (e) => {
      const t = e.target;
      if (!ready || !e.clipboardData || (t && t.closest && t.closest('[data-checker-paste]'))) return;
      const inside = root.contains(t);
      const editable = t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
      if (editable && t !== input) return;
      const file = e.clipboardData.files && e.clipboardData.files[0];
      const s = e.clipboardData.getData('text/plain');
      if (inside && file) {
        e.preventDefault();
        checkFile(file);
      } else if (s && (inside || ((t === document.body || t === document.documentElement) && s.trim().startsWith('{')))) {
        e.preventDefault();
        checkText(s, text.sourcePaste);
      }
    });

    // addPaste adds a box for pasting the file's text, for readers who have
    // the JSON but not a file.
    function addPaste() {
      if (root.querySelector('[data-checker-paste]')) return;
      const d = el('details', { class: 'tech checker-paste', 'data-checker-paste': '' });
      const summary = el('summary');
      summary.append(icon('chevron'), el('span', {}, text.pasteOpen));
      const id = 'checker-paste-text';
      const label = el('label', { for: id, class: 'checker-paste-label' }, text.pasteLabel);
      const area = el('textarea', {
        id, class: 'checker-paste-text', rows: '6', spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off',
      });
      const go = el('button', { type: 'button', class: 'btn' }, text.pasteButton);
      const note = el('p', { class: 'checker-paste-note', 'aria-live': 'polite' });
      go.addEventListener('click', () => {
        if (!area.value.trim()) {
          note.textContent = text.pasteEmpty;
          area.focus();
          return;
        }
        note.textContent = '';
        checkText(area.value, text.sourcePaste);
      });
      // A paste into the empty box checks it at once.
      area.addEventListener('paste', () => {
        if (area.value.trim()) return;
        setTimeout(() => {
          if (area.value.trim()) {
            note.textContent = '';
            checkText(area.value, text.sourcePaste);
          }
        }, 0);
      });
      d.append(summary, label, area, go, note);
      // Pasting is another way to give a file, so it sits right under the
      // drop zone, before the samples.
      const after = input.closest('label') || input;
      after.after(d);
    }

    // The line changes now, though the download waits for the page to load.
    // A browser without WebAssembly hears so at once.
    if (wasmSupported()) setPending(text.loadingStart);
    else load();
    return load;
  }

  // start mounts the checker at once, so the page says it is loading. The
  // module is a few megabytes, so the download waits for the page's own
  // files and never slows the page's first paint.
  function start() {
    const root = document.getElementById('checker');
    if (!root || root.hasAttribute('data-checker-mounted')) return;
    root.setAttribute('data-checker-mounted', '');
    linkStyles();
    const load = mount(root);
    if (document.readyState === 'complete') load();
    else window.addEventListener('load', () => load(), { once: true });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();

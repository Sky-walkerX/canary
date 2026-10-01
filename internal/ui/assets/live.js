// Canary dashboard update check. No framework, no outside requests.
//
// It polls /state.etag every 5 s while the tab is visible and shows a
// non-modal status bar when something changed. The bar stays until the
// reader acts on it. Only the dashboard loads this file. The public site
// never ships it, so a recorded run can't look live.
//
// It holds no wording of its own. Every sentence comes from data attributes
// the server rendered from Canary's wording table.
(function () {
  'use strict';

  function pad(n) { return n < 10 ? '0' + n : String(n); }

  function initUpdates() {
    var bar = document.getElementById('update-bar');
    var body = document.body;
    if (!bar || !window.fetch || !body) return;

    var pageETag = body.getAttribute('data-etag');
    var pageBuild = body.getAttribute('data-build');
    var pageFindings = parseInt(body.getAttribute('data-findings') || '0', 10) || 0;
    var baseTitle = document.title;
    var shownKey = '';
    var dismissedKey = '';
    var lostSince = null;
    var timer = null;

    function msg(name) { return bar.getAttribute('data-msg-' + name) || ''; }

    function render(key, text, canReload) {
      if (key === shownKey || key === dismissedKey) return;
      shownKey = key;
      while (bar.firstChild) bar.removeChild(bar.firstChild);
      var inner = document.createElement('div');
      inner.className = 'update-inner';
      var p = document.createElement('p');
      p.className = 'update-text';
      p.textContent = text;
      inner.appendChild(p);
      if (canReload) {
        var reload = document.createElement('button');
        reload.type = 'button';
        reload.className = 'btn btn-small';
        reload.textContent = bar.getAttribute('data-reload') || 'Reload';
        reload.addEventListener('click', function () { window.location.reload(); });
        inner.appendChild(reload);
      }
      var dismiss = document.createElement('button');
      dismiss.type = 'button';
      dismiss.className = 'btn btn-small';
      dismiss.textContent = bar.getAttribute('data-dismiss') || 'Dismiss';
      dismiss.addEventListener('click', function () {
        dismissedKey = shownKey;
        shownKey = '';
        while (bar.firstChild) bar.removeChild(bar.firstChild);
        body.classList.remove('has-bar');
      });
      inner.appendChild(dismiss);
      bar.appendChild(inner);
      body.classList.add('has-bar');
    }

    function decide(s) {
      var grew = typeof s.findings === 'number' ? s.findings - pageFindings : 0;
      document.title = grew > 0 ? '(' + grew + ') ' + baseTitle : baseTitle;
      if (s.build !== pageBuild) {
        render('updated', msg('updated'), true);
      } else if (grew > 0) {
        var text = grew === 1 ? msg('finding') : msg('findings').replace('{n}', String(grew));
        render('finding-' + grew, text, true);
      } else if (s.etag !== pageETag) {
        render('results-' + s.etag, msg('results'), true);
      } else if (shownKey === 'lost') {
        render('back', msg('back'), false);
      }
    }

    function schedule() {
      window.clearTimeout(timer);
      if (document.visibilityState === 'visible') {
        timer = window.setTimeout(poll, 5000);
      }
    }

    function poll() {
      window.fetch('/state.etag', { cache: 'no-store', credentials: 'same-origin' })
        .then(function (r) {
          if (!r.ok) throw new Error('status ' + r.status);
          return r.json();
        })
        .then(function (s) {
          lostSince = null;
          if (dismissedKey === 'lost') dismissedKey = '';
          decide(s);
        }, function () {
          if (!lostSince) lostSince = new Date();
          var at = pad(lostSince.getHours()) + ':' + pad(lostSince.getMinutes());
          render('lost', msg('lost').replace('{time}', at), false);
        })
        .then(schedule, schedule);
    }

    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'visible') {
        poll();
      } else {
        window.clearTimeout(timer);
      }
    });
    schedule();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initUpdates);
  } else {
    initUpdates();
  }
})();

// Canary's page script, for the dashboard and the public site. No framework,
// no outside requests.
//
// It does two things, and every page works without it:
//   1. Applies the reader's theme choice before the page paints.
//   2. Shows copy buttons and copies values to the clipboard.
//
// The dashboard's update check lives in live.js, which only the dashboard
// loads. The public site, recorded runs included, never ships it.
//
// It holds no wording of its own. Every sentence comes from data attributes
// the server rendered from Canary's wording table.
(function () {
  'use strict';

  var root = document.documentElement;
  var THEME_KEY = 'canary-theme';

  function readTheme() {
    try {
      var v = window.localStorage.getItem(THEME_KEY);
      return v === 'light' || v === 'dark' ? v : 'auto';
    } catch (e) {
      return 'auto';
    }
  }

  function writeTheme(v) {
    try {
      if (v === 'auto') {
        window.localStorage.removeItem(THEME_KEY);
      } else {
        window.localStorage.setItem(THEME_KEY, v);
      }
    } catch (e) {
      // Storage can be blocked. The choice then lasts for this page only.
    }
  }

  function applyTheme(v) {
    if (v === 'light' || v === 'dark') {
      root.setAttribute('data-theme', v);
    } else {
      root.removeAttribute('data-theme');
    }
  }

  applyTheme(readTheme());

  function initTheme() {
    var button = document.querySelector('[data-theme-toggle]');
    if (!button) return;
    var label = button.querySelector('[data-theme-label]');
    var order = ['auto', 'light', 'dark'];
    var current = readTheme();
    function show() {
      if (label) label.textContent = button.getAttribute('data-label-' + current) || current;
    }
    show();
    button.hidden = false;
    button.addEventListener('click', function () {
      current = order[(order.indexOf(current) + 1) % order.length];
      applyTheme(current);
      writeTheme(current);
      show();
    });
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.className = 'sr-only';
      document.body.appendChild(area);
      area.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(area);
      if (ok) { resolve(); } else { reject(new Error('copy failed')); }
    });
  }

  function initCopy() {
    var status = document.querySelector('[data-copy-status]');
    var buttons = document.querySelectorAll('[data-copy]');
    Array.prototype.forEach.call(buttons, function (button) {
      button.hidden = false;
      button.addEventListener('click', function () {
        var text = button.getAttribute('data-copy') || '';
        var label = button.querySelector('[data-copy-label]');
        copyText(text).then(function () {
          if (label) label.textContent = button.getAttribute('data-copied') || label.textContent;
          if (status) status.textContent = (button.getAttribute('data-copied') || '') + '.';
        }, function () {
          // Copying was refused. The value stays on the page as selectable text.
        });
      });
    });
  }

  function init() {
    initTheme();
    initCopy();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

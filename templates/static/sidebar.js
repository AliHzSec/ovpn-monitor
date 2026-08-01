/* ==========================================================================
   sidebar.js — shared sidebar behaviour for every panel page.

   Plain vanilla JS, no framework and no build step. Loaded with `defer` so the
   markup exists by the time it runs.

   Responsibilities:
     1. Mobile hamburger / overlay toggle.
     2. Marking the nav item that matches the current URL as active.
     3. The "Panel Settings" accordion: clicking the parent expands a submenu
        of setting sections instead of navigating.

   Pages that had this logic inline no longer do — it lives here once so the
   three panel pages can never drift apart.
   ========================================================================== */
(function () {
    'use strict';

    var path = window.location.pathname;

    /* ── Mobile sidebar ──────────────────────────────────────────────────── */
    var sidebar = document.getElementById('sidebar');
    var overlay = document.getElementById('sidebar-overlay');
    var hamburger = document.getElementById('hamburger');

    if (sidebar && hamburger) {
        hamburger.addEventListener('click', function () {
            var open = sidebar.classList.toggle('open');
            if (overlay) overlay.classList.toggle('visible', open);
        });
    }
    if (overlay && sidebar) {
        overlay.addEventListener('click', function () {
            sidebar.classList.remove('open');
            overlay.classList.remove('visible');
        });
    }

    /* ── Active nav item ─────────────────────────────────────────────────────
       Derived from the URL rather than hardcoded per template, so every page
       highlights consistently. Client detail pages (/panel/clients/<name>)
       keep the Clients entry lit. */
    var onSettings = path === '/settings' || path.indexOf('/settings/') === 0;

    function markActive(id) {
        var el = document.getElementById(id);
        if (el) el.classList.add('active');
    }

    if (path === '/panel') {
        markActive('nav-overview');
    } else if (path.indexOf('/panel/clients') === 0) {
        markActive('nav-clients');
    } else if (onSettings) {
        markActive('nav-settings');
    }

    /* ── Settings submenu ────────────────────────────────────────────────────
       Expanded state persists in localStorage so the menu doesn't snap shut
       every time the user navigates. A settings page always forces it open,
       because collapsing the menu you are currently inside would hide the
       highlighted item. */
    var group = document.getElementById('nav-settings-group');
    var parent = document.getElementById('nav-settings');
    var STORAGE_KEY = 'panel.settingsMenuOpen';

    function readStored() {
        try {
            return window.localStorage.getItem(STORAGE_KEY) === '1';
        } catch (e) {
            return false; // private mode / storage disabled
        }
    }

    function writeStored(open) {
        try {
            window.localStorage.setItem(STORAGE_KEY, open ? '1' : '0');
        } catch (e) {
            /* not fatal — the menu just won't remember across loads */
        }
    }

    if (group && parent) {
        var startOpen = onSettings || readStored();
        group.classList.toggle('open', startOpen);
        parent.setAttribute('aria-expanded', startOpen ? 'true' : 'false');

        parent.addEventListener('click', function () {
            var open = group.classList.toggle('open');
            parent.setAttribute('aria-expanded', open ? 'true' : 'false');
            writeStored(open);
        });

        /* Highlight the section currently being edited. The sub-items link to
           /settings/<section>, so an exact pathname match is enough. */
        group.querySelectorAll('.nav-sub a').forEach(function (link) {
            if (link.getAttribute('href') === path) {
                link.classList.add('active');
                link.setAttribute('aria-current', 'page');
            }
        });
    }
})();

// --- Hacker mode: a terminal look over any theme, toggled with the ` key ---
// Purely visual. It reads the page's state (jumpState, summaryState, network, currentEmail, lastInput
// from v2_render.js) and never changes a check. Styles are in v2_hacker.css.
(() => {
    const root = document.documentElement;
    const storageKey = 'emailParserHacker';
    const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
    const defaultPlaceholder = pasteInput.placeholder;
    const hackerPlaceholder = '> paste the raw message source (RFC 5322). It is parsed in this tab as you type_';
    const state = { on: false, statusTimer: 0 };

    // --- Backdrop rain: the loaded message's own header bytes fall down the screen (random hex before one is loaded) ---
    const hexPool = '0123456789abcdef';
    const rain = { canvas: null, ctx: null, frame: 0, last: 0, cols: [], pool: hexPool, sequential: false,
        email: undefined, size: 16, width: 0, height: 0 };

    function updateRainPool() {
        if (rain.email === currentEmail) return;
        rain.email = currentEmail;
        const text = String(currentEmail?.rawHeaders ?? '').replace(/[^\x21-\x7e]+/g, '');
        rain.sequential = text.length >= 64;
        rain.pool = rain.sequential ? text : hexPool;
        for (const col of rain.cols) col.index = Math.floor(Math.random() * rain.pool.length);
    }

    function newColumn(scatter) {
        return { row: scatter ? -Math.floor(Math.random() * 60) : 0, speed: 0.35 + Math.random() * 0.75, step: 0,
            index: Math.floor(Math.random() * rain.pool.length), head: null };
    }

    function resizeRain() {
        const ratio = Math.min(devicePixelRatio || 1, 2);
        rain.width = innerWidth;
        rain.height = innerHeight;
        rain.canvas.width = Math.round(innerWidth * ratio);
        rain.canvas.height = Math.round(innerHeight * ratio);
        // Resizing a canvas resets its context, so set these after.
        rain.ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
        rain.ctx.font = `${rain.size - 3}px ${getComputedStyle(document.body).getPropertyValue('--font-mono')}`;
        rain.ctx.textBaseline = 'top';
        rain.cols = Array.from({ length: Math.ceil(innerWidth / rain.size) }, (_, x) => rain.cols[x] ?? newColumn(true));
    }

    function drawRain(time) {
        rain.frame = requestAnimationFrame(drawRain);
        // About 20 frames a second is plenty for a backdrop.
        if (time - rain.last < 50) return;
        rain.last = time;
        const { ctx, size } = rain;
        ctx.fillStyle = 'rgba(2, 6, 4, 0.14)';
        ctx.fillRect(0, 0, rain.width, rain.height);
        rain.cols.forEach((col, x) => {
            col.step += col.speed;
            if (col.step < 1) return;
            col.step -= 1;
            const left = x * size;
            const top = col.row * size;
            // The previous head turns green; the new one is drawn bright.
            if (col.head) {
                ctx.fillStyle = '#00ff88';
                ctx.fillText(col.head, left, top - size);
            }
            const character = rain.sequential ? rain.pool[col.index++ % rain.pool.length]
                : rain.pool[Math.floor(Math.random() * rain.pool.length)];
            ctx.fillStyle = '#e1ffec';
            ctx.fillText(character, left, top);
            col.head = character;
            col.row += 1;
            if (top > rain.height && Math.random() > 0.96) Object.assign(col, newColumn(false));
        });
    }

    function startRain() {
        if (rain.canvas || reducedMotion.matches) return;
        rain.canvas = document.createElement('canvas');
        rain.canvas.id = 'hacker-rain';
        rain.canvas.setAttribute('aria-hidden', 'true');
        rain.ctx = rain.canvas.getContext('2d');
        document.body.prepend(rain.canvas);
        rain.email = undefined;
        updateRainPool();
        resizeRain();
        addEventListener('resize', resizeRain);
        rain.frame = requestAnimationFrame(drawRain);
    }

    function stopRain() {
        if (!rain.canvas) return;
        cancelAnimationFrame(rain.frame);
        removeEventListener('resize', resizeRain);
        rain.canvas.remove();
        rain.canvas = rain.ctx = null;
        rain.cols = [];
    }

    // --- Text that "decrypts": random glyphs settle into the real text, left to right ---
    const glyphs = '!<>-_\\/[]{}=+*^?#$%&01ABCDEF';
    const scrambling = new Map();

    function scramble(node, duration = 650) {
        if (!state.on || reducedMotion.matches || !node.data.trim()) return;
        const running = scrambling.get(node);
        const final = running?.final ?? node.data;
        if (running) cancelAnimationFrame(running.frame);
        const start = performance.now();
        const step = now => {
            const progress = Math.min(1, (now - start) / duration);
            const settled = Math.floor(progress * final.length);
            node.data = final.slice(0, settled)
                + final.slice(settled).replace(/\S/g, () => glyphs[Math.floor(Math.random() * glyphs.length)]);
            if (progress < 1) scrambling.set(node, { final, frame: requestAnimationFrame(step) });
            else scrambling.delete(node);
        };
        scrambling.set(node, { final, frame: requestAnimationFrame(step) });
    }

    function scrambleAll(selector = 'h1, .tagline, .drop-title, .section-heading > span:first-child') {
        for (const element of document.querySelectorAll(selector)) {
            for (const child of element.childNodes) {
                if (child.nodeType === Node.TEXT_NODE) scramble(child);
            }
        }
    }

    function settleScrambles() {
        for (const [node, { final, frame }] of scrambling) {
            cancelAnimationFrame(frame);
            node.data = final;
        }
        scrambling.clear();
    }

    // The overall status decrypts each time it changes.
    const glanceSlot = document.getElementById('summary-glance');
    let lastGlance = '';
    new MutationObserver(() => {
        const label = glanceSlot.querySelector('.glance-label');
        const text = label?.textContent ?? '';
        if (text === lastGlance) return;
        lastGlance = text;
        if (label?.firstChild) scramble(label.firstChild, 500);
    }).observe(glanceSlot, { childList: true });

    // Each new message decrypts the section titles. A recheck hides and shows the results in one go, so it doesn't.
    let resultsShown = !resultsDiv.classList.contains('hidden');
    new MutationObserver(() => {
        const shown = !resultsDiv.classList.contains('hidden');
        if (shown && !resultsShown) scrambleAll('#results .section-heading > span:first-child');
        resultsShown = shown;
    }).observe(resultsDiv, { attributes: true, attributeFilter: ['class'] });

    // --- Status line along the bottom, like a terminal multiplexer's ---
    const statusBar = document.createElement('div');
    statusBar.className = 'hacker-status';
    // Everything it shows is on the page already.
    statusBar.setAttribute('aria-hidden', 'true');
    let statusHtml = '';

    function renderStatus() {
        updateRainPool();
        const loaded = !resultsDiv.classList.contains('hidden') && Boolean(currentEmail);
        const file = loaded ? lastInput?.source?.name ?? 'stdin' : 'no input';
        const checks = ['dkim', 'spf', 'dmarc', 'arc'].map(id => {
            const result = loaded ? jumpState['section-' + id]?.result : null;
            const shown = !result ? '-' : result === 'pending' ? '…' : result;
            return `<span><span class="hs-key">${id}:</span><span class="is-${jumpTone(result) ?? 'neutral'}">${escapeHtml(shown)}</span></span>`;
        }).join('');
        const glance = loaded ? summaryState.glance : null;
        const where = loaded && jumpActive ? jumpLabels[jumpActive] : '';
        const html = `<span class="hs-mode">HACKER</span>
            <span class="hs-file">${escapeHtml(file)}</span>
            ${glance ? `<span class="is-${glance.tone}">${escapeHtml(String(glance.label).toLowerCase())}</span>` : ''}
            <span class="hs-checks">${checks}</span>
            <span class="hs-spacer"></span>
            ${where ? `<span class="hs-where">§ ${escapeHtml(where.toLowerCase())}</span>` : ''}
            <span class="hs-net">net:${network.offline ? 'offline' : 'online'} · ${network.requests.length} req</span>
            <span class="hs-clock">${new Date().toISOString().slice(11, 19)}Z</span>
            <span><kbd>\`</kbd> exit</span>`;
        if (html !== statusHtml) statusBar.innerHTML = statusHtml = html;
    }

    // --- Boot screen: a few lines about what's loaded, then the page flickers on ---
    let boot = null;

    function headerCount() {
        return String(currentEmail?.rawHeaders ?? '').split(/\r?\n/).filter(line => /^[^\s:]+:/.test(line)).length;
    }

    function bootLines() {
        const ok = '<span class="ok">[ ok ]</span>';
        const modules = [['parser', typeof EmailParser], ['dkim', typeof DkimValidator], ['arc', typeof ArcValidator],
            ['spf', typeof SpfValidator], ['dmarc', typeof DmarcValidator]]
            .filter(([, type]) => type === 'function').map(([name]) => name);
        const loaded = !resultsDiv.classList.contains('hidden') && currentEmail;
        const input = loaded ? `${escapeHtml(lastInput?.source?.name ?? 'stdin')} · ${headerCount()} header fields` : 'waiting for a message';
        return [
            '<span class="dim">email-inspector :: hacker mode</span>',
            '',
            `${ok} modules    <span class="val">${modules.join(' · ')}</span>`,
            globalThis.crypto?.subtle ? `${ok} webcrypto  <span class="val">crypto.subtle ready</span>`
                : '<span class="off">[warn]</span> webcrypto  <span class="val">unavailable, signatures can\'t be checked</span>',
            network.offline ? '<span class="off">[ -- ]</span> network    <span class="val">offline mode, no lookups</span>'
                : `${ok} network    <span class="val">dns-over-https · cloudflare-dns.com</span>`,
            `${ok} input      <span class="val">${input}</span>`,
            '',
            '<span class="dim">press ` to exit</span> <span class="cursor">█</span>'
        ];
    }

    function showBoot() {
        if (reducedMotion.matches) return;
        closeBoot(true);
        const overlay = document.createElement('div');
        overlay.className = 'hacker-boot';
        overlay.setAttribute('aria-hidden', 'true');
        const screen = document.createElement('pre');
        overlay.append(screen);
        overlay.addEventListener('click', () => closeBoot());
        document.body.append(overlay);
        const lines = bootLines();
        let shown = 0;
        boot = { overlay, timer: setInterval(() => {
            if (shown < lines.length) {
                screen.innerHTML = lines.slice(0, ++shown).join('\n');
                return;
            }
            clearInterval(boot.timer);
            boot.timer = setTimeout(() => closeBoot(), 450);
        }, 85) };
    }

    function closeBoot(instant = false) {
        if (!boot) return;
        clearInterval(boot.timer);
        clearTimeout(boot.timer);
        const { overlay } = boot;
        boot = null;
        if (instant) {
            overlay.remove();
            return;
        }
        overlay.classList.add('is-leaving');
        setTimeout(() => overlay.remove(), 300);
        powerUp();
    }

    let powerTimer = 0;
    function powerUp() {
        root.classList.add('hacker-powerup');
        scrambleAll();
        clearTimeout(powerTimer);
        powerTimer = setTimeout(() => root.classList.remove('hacker-powerup'), 1100);
    }

    // --- Pointer glow: the section under the pointer lights up around it ---
    let spot = null;
    let spotFrame = 0;
    let pointer = null;

    function clearSpot() {
        spot?.style.removeProperty('--mx');
        spot?.style.removeProperty('--my');
        spot = null;
    }

    function moveSpot() {
        spotFrame = 0;
        const target = pointer.target instanceof Element ? pointer.target.closest('.section, #drop-zone') : null;
        if (spot !== target) clearSpot();
        if (!target || !state.on) return;
        spot = target;
        const box = target.getBoundingClientRect();
        target.style.setProperty('--mx', `${pointer.clientX - box.left}px`);
        target.style.setProperty('--my', `${pointer.clientY - box.top}px`);
    }

    document.addEventListener('pointermove', event => {
        if (!state.on || event.pointerType === 'touch') return;
        pointer = event;
        if (!spotFrame) spotFrame = requestAnimationFrame(moveSpot);
    }, { passive: true });

    // --- Switching it on and off ---
    function announce(html) {
        copyToast.classList.remove('is-error');
        copyToast.innerHTML = html;
        copyToast.classList.add('visible');
        // Shares the copy toast's timer, so neither cuts the other short.
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => copyToast.classList.remove('visible'), 1800);
    }

    function setHacker(on, { animate = true } = {}) {
        if (on === state.on) return;
        state.on = on;
        root.classList.toggle('hacker-mode', on);
        try {
            localStorage.setItem(storageKey, on ? '1' : '0');
        } catch {
            // Only persistence is optional.
        }
        if (on) {
            document.body.append(statusBar);
            renderStatus();
            state.statusTimer = setInterval(renderStatus, 500);
            startRain();
            pasteInput.placeholder = hackerPlaceholder;
            if (animate) {
                if (reducedMotion.matches) announce('<span>Hacker mode on</span>');
                else showBoot();
            }
        } else {
            closeBoot(true);
            clearInterval(state.statusTimer);
            statusBar.remove();
            statusHtml = '';
            stopRain();
            settleScrambles();
            clearSpot();
            clearTimeout(powerTimer);
            root.classList.remove('hacker-powerup');
            pasteInput.placeholder = defaultPlaceholder;
            if (animate) announce('<span>Hacker mode off. Press</span><kbd>`</kbd><span>to turn it back on</span>');
        }
    }

    // ` (the key left of 1, the console key in many games) toggles it, except while typing.
    document.addEventListener('keydown', event => {
        const hotkey = event.key === '`' || event.code === 'Backquote';
        if (boot && !hotkey) closeBoot();
        if (!hotkey || event.ctrlKey || event.metaKey || event.altKey || event.repeat || event.isComposing) return;
        if (event.target instanceof Element && event.target.closest('input, textarea, select, [contenteditable]:not([contenteditable="false"])')) return;
        event.preventDefault();
        setHacker(!state.on);
    });

    reducedMotion.addEventListener('change', () => {
        if (!state.on) return;
        if (reducedMotion.matches) {
            stopRain();
            closeBoot(true);
            settleScrambles();
        } else {
            startRain();
        }
    });

    let saved = null;
    try {
        saved = localStorage.getItem(storageKey);
    } catch {
        // Without storage it starts off each time.
    }
    if (saved === '1') setHacker(true, { animate: false });
})();

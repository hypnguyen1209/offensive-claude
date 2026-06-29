/*
 * frida_universal.js - cross-platform Frida 17.x instrumentation toolkit.
 *
 * Capabilities:
 *   - Universal Android SSL unpinning (OkHttp, X509TrustManager, Conscrypt, ChainCleaner)
 *   - Anti-anti-debug: stub ptrace, force IsDebuggerPresent=0, scrub TracerPid reads
 *   - Native function tracing helper + JNI_OnLoad logging
 *
 * Usage:
 *   Android (spawn):   frida -U -f com.target.app -l frida_universal.js --no-pause
 *   Android (attach):  frida -U -n com.target.app -l frida_universal.js
 *   Linux/Windows:     frida -p <pid> -l frida_universal.js
 *   Trace a native fn: edit TRACE_EXPORTS below.
 *
 * Tested with frida 17.x. Java hooks no-op on non-JVM targets (wrapped in availability checks).
 */

'use strict';

// ----- configurable: native exports to trace (name or "module!name") -----
const TRACE_EXPORTS = ['strcmp', 'memcmp'];   // add target-specific functions here

function log(tag, msg) { console.log('[' + tag + '] ' + msg); }

/* ---------------------------------------------------------------------------
 * 1. Anti-anti-debug (native, all platforms)
 * ------------------------------------------------------------------------- */
function neutralizeAntiDebug() {
  // Windows: IsDebuggerPresent -> 0
  const k32 = Process.platform === 'windows' ? 'kernel32.dll' : null;
  if (k32) {
    const idp = Module.findExportByName(k32, 'IsDebuggerPresent');
    if (idp) {
      Interceptor.replace(idp, new NativeCallback(() => 0, 'int', []));
      log('antidebug', 'IsDebuggerPresent -> 0');
    }
    const gtc = Module.findExportByName(k32, 'GetThreadContext');
    if (gtc) {
      Interceptor.attach(gtc, {
        onLeave() {
          // CONTEXT.Dr0..Dr3 live at offsets 0x48..0x60 in x64 CONTEXT; zero them.
          // (left as a hook point — fill ctx ptr from args in onEnter for full impl)
        }
      });
    }
  }

  // Linux/Android: ptrace -> 0 (defeats PTRACE_TRACEME self-attach checks)
  const ptrace = Module.findExportByName(null, 'ptrace');
  if (ptrace) {
    Interceptor.replace(ptrace,
      new NativeCallback(() => 0, 'long', ['int', 'int', 'pointer', 'pointer']));
    log('antidebug', 'ptrace -> 0');
  }

  // Scrub TracerPid from /proc/self/status reads (Linux/Android)
  const openPtr = Module.findExportByName(null, 'open');
  if (openPtr) {
    let lastStatus = false;
    Interceptor.attach(openPtr, {
      onEnter(args) {
        try { lastStatus = (args[0].readUtf8String() || '').indexOf('/status') !== -1; }
        catch (e) { lastStatus = false; }
      }
    });
    const readPtr = Module.findExportByName(null, 'read');
    if (readPtr) {
      Interceptor.attach(readPtr, {
        onEnter(args) { this.buf = args[1]; this.want = lastStatus; },
        onLeave(retval) {
          if (!this.want || retval.toInt32() <= 0) return;
          try {
            let s = this.buf.readUtf8String(retval.toInt32());
            if (s.indexOf('TracerPid:') !== -1) {
              s = s.replace(/TracerPid:\t\d+/, 'TracerPid:\t0');
              this.buf.writeUtf8String(s);
              log('antidebug', 'scrubbed TracerPid');
            }
          } catch (e) {}
        }
      });
    }
  }
}

/* ---------------------------------------------------------------------------
 * 2. Universal Android SSL unpinning (layered)
 * ------------------------------------------------------------------------- */
function unpinSSL() {
  if (typeof Java === 'undefined' || !Java.available) return;
  Java.perform(function () {
    // okhttp3.CertificatePinner.check
    try {
      const CP = Java.use('okhttp3.CertificatePinner');
      ['check', 'check$okhttp'].forEach(function (m) {
        if (CP[m]) {
          CP[m].overload('java.lang.String', 'java.util.List').implementation =
            function () { log('ssl', 'okhttp CertificatePinner.' + m + ' bypassed'); };
        }
      });
    } catch (e) {}

    // javax.net.ssl.X509TrustManager via custom no-op TrustManager
    try {
      const X509TM = Java.use('javax.net.ssl.X509TrustManager');
      const SSLContext = Java.use('javax.net.ssl.SSLContext');
      const TrustManager = Java.registerClass({
        name: 'org.re.NoopTrustManager',
        implements: [X509TM],
        methods: {
          checkClientTrusted() {},
          checkServerTrusted() {},
          getAcceptedIssuers() { return []; }
        }
      });
      const init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom');
      init.implementation = function (km, tm, sr) {
        log('ssl', 'SSLContext.init -> noop TrustManager');
        init.call(this, km, [TrustManager.$new()], sr);
      };
    } catch (e) {}

    // Conscrypt TrustManagerImpl.checkServerTrusted (returns the chain unverified)
    try {
      const TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
      ['checkServerTrusted'].forEach(function (m) {
        TMI[m].overloads.forEach(function (ov) {
          ov.implementation = function () {
            log('ssl', 'Conscrypt TrustManagerImpl.' + m + ' bypassed');
            // return empty/cleaned chain
            return Java.use('java.util.ArrayList').$new();
          };
        });
      });
    } catch (e) {}

    // CertificateChainCleaner.check
    try {
      const CCC = Java.use('okhttp3.internal.tls.CertificateChainCleaner');
      CCC.check.overload('java.lang.String', 'java.util.List').implementation =
        function (h, certs) { log('ssl', 'ChainCleaner.check bypassed'); return certs; };
    } catch (e) {}

    log('ssl', 'layered SSL unpinning installed');
  });
}

/* ---------------------------------------------------------------------------
 * 3. Native tracing + JNI_OnLoad logging
 * ------------------------------------------------------------------------- */
function traceExports() {
  TRACE_EXPORTS.forEach(function (spec) {
    let mod = null, name = spec;
    if (spec.indexOf('!') !== -1) { const p = spec.split('!'); mod = p[0]; name = p[1]; }
    const addr = Module.findExportByName(mod, name);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter(args) {
        let a0 = '', a1 = '';
        try { a0 = args[0].readUtf8String(); } catch (e) { a0 = args[0]; }
        try { a1 = args[1].readUtf8String(); } catch (e) { a1 = args[1]; }
        log('trace', name + '(' + a0 + ', ' + a1 + ')');
      },
      onLeave(retval) { log('trace', name + ' -> ' + retval); }
    });
    log('trace', 'hooked ' + spec);
  });

  // log every native library load (find JNI-heavy targets)
  const dlopen = Module.findExportByName(null,
    Process.platform === 'windows' ? 'LoadLibraryW' : 'dlopen');
  if (dlopen) {
    Interceptor.attach(dlopen, {
      onEnter(args) {
        try { log('dlopen', args[0].readUtf8String()); } catch (e) {}
      }
    });
  }
}

/* --------------------------------------------------------------------------- */
neutralizeAntiDebug();
unpinSSL();
traceExports();
log('init', 'frida_universal.js loaded on ' + Process.platform + '/' + Process.arch);

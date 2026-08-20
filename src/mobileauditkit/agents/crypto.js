Java.perform(function () {
  let attempted = 0;
  let installed = 0;
  function attempt(fn) { attempted += 1; try { fn(); installed += 1; } catch (_) {} }
  function emit(algorithm, api) { send({event: 'crypto_algorithm', algorithm: String(algorithm), api: api, sensitive_data: false}); }
  attempt(function () {
    const Cipher = Java.use('javax.crypto.Cipher');
    const cipherGet = Cipher.getInstance.overload('java.lang.String');
    cipherGet.implementation = function (transformation) { emit(transformation, 'javax.crypto.Cipher.getInstance'); return cipherGet.call(this, transformation); };
  });
  attempt(function () {
    const MessageDigest = Java.use('java.security.MessageDigest');
    const digestGet = MessageDigest.getInstance.overload('java.lang.String');
    digestGet.implementation = function (algorithm) { emit(algorithm, 'java.security.MessageDigest.getInstance'); return digestGet.call(this, algorithm); };
  });
  attempt(function () {
    const Mac = Java.use('javax.crypto.Mac');
    const macGet = Mac.getInstance.overload('java.lang.String');
    macGet.implementation = function (algorithm) { emit(algorithm, 'javax.crypto.Mac.getInstance'); return macGet.call(this, algorithm); };
  });
  send({event: 'hook_health', module: 'crypto', state: installed === attempted && installed > 0 ? 'READY' : 'DEGRADED', hooks_attempted: attempted, hooks_installed: installed, sensitive_data: false});
});

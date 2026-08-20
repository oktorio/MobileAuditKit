Java.perform(function () {
  let attempted = 0;
  let installed = 0;
  function hookPrompt(className) {
    attempted += 1;
    try {
      const Prompt = Java.use(className);
      Prompt.authenticate.overloads.forEach(function (ov) {
        const argTypes = ov.argumentTypes.map(function (t) { return t.className; });
        const hasCrypto = argTypes.some(function (name) { return name && name.indexOf('CryptoObject') >= 0; });
        ov.implementation = function () { send({event: 'biometric_authentication', api: className + '.authenticate', crypto_bound: hasCrypto, auth_result_modified: false}); return ov.apply(this, arguments); };
      });
      installed += 1;
    } catch (_) {}
  }
  hookPrompt('androidx.biometric.BiometricPrompt');
  hookPrompt('android.hardware.biometrics.BiometricPrompt');
  send({event: 'hook_health', module: 'authentication', state: installed === attempted && installed > 0 ? 'READY' : 'DEGRADED', hooks_attempted: attempted, hooks_installed: installed, sensitive_data: false});
});

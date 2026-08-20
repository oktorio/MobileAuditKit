Java.perform(function () {
  function hookPrompt(className) {
    try {
      const Prompt = Java.use(className);
      Prompt.authenticate.overloads.forEach(function (ov) {
        const argTypes = ov.argumentTypes.map(function (t) { return t.className; });
        const hasCrypto = argTypes.some(function (name) { return name && name.indexOf('CryptoObject') >= 0; });
        ov.implementation = function () {
          send({event: 'biometric_authentication', api: className + '.authenticate', crypto_bound: hasCrypto, auth_result_modified: false});
          return ov.apply(this, arguments);
        };
      });
    } catch (_) {}
  }
  hookPrompt('androidx.biometric.BiometricPrompt');
  hookPrompt('android.hardware.biometrics.BiometricPrompt');
});

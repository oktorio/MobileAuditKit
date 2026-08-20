Java.perform(function () {
  function emit(algorithm, api) {
    send({event: 'crypto_algorithm', algorithm: String(algorithm), api: api, sensitive_data: false});
  }
  try {
    const Cipher = Java.use('javax.crypto.Cipher');
    const cipherGet = Cipher.getInstance.overload('java.lang.String');
    cipherGet.implementation = function (transformation) {
      emit(transformation, 'javax.crypto.Cipher.getInstance');
      return cipherGet.call(this, transformation);
    };
  } catch (_) {}
  try {
    const MessageDigest = Java.use('java.security.MessageDigest');
    const digestGet = MessageDigest.getInstance.overload('java.lang.String');
    digestGet.implementation = function (algorithm) {
      emit(algorithm, 'java.security.MessageDigest.getInstance');
      return digestGet.call(this, algorithm);
    };
  } catch (_) {}
  try {
    const Mac = Java.use('javax.crypto.Mac');
    const macGet = Mac.getInstance.overload('java.lang.String');
    macGet.implementation = function (algorithm) {
      emit(algorithm, 'javax.crypto.Mac.getInstance');
      return macGet.call(this, algorithm);
    };
  } catch (_) {}
});

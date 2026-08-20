Java.perform(function () {
  function origin(text) {
    try {
      const URI = Java.use('java.net.URI');
      const uri = URI.$new(String(text));
      return {scheme: uri.getScheme() ? String(uri.getScheme()) : null, host: uri.getHost() ? String(uri.getHost()) : null, port: Number(uri.getPort())};
    } catch (_) { return {scheme: null, host: null, port: -1}; }
  }
  function checkUrl(value, api) {
    const parsed = origin(value);
    if (parsed.scheme && parsed.scheme.toLowerCase() === 'http') send({event: 'network_cleartext', api: api, origin: parsed, query_captured: false});
  }
  try {
    const URL = Java.use('java.net.URL');
    const init = URL.$init.overload('java.lang.String');
    init.implementation = function (value) { checkUrl(value, 'java.net.URL'); return init.call(this, value); };
  } catch (_) {}
  try {
    const Builder = Java.use('okhttp3.Request$Builder');
    const url = Builder.url.overload('java.lang.String');
    url.implementation = function (value) { checkUrl(value, 'okhttp3.Request.Builder.url'); return url.call(this, value); };
  } catch (_) {}
  try {
    const SSLContext = Java.use('javax.net.ssl.SSLContext');
    const initTls = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
    initTls.implementation = function (kms, tms, random) {
      const classes = [];
      if (tms) for (let i = 0; i < tms.length; i++) try { classes.push(String(tms[i].getClass().getName())); } catch (_) {}
      send({event: 'network_trust_manager', api: 'SSLContext.init', trust_manager_classes: classes, data_captured: false});
      return initTls.call(this, kms, tms, random);
    };
  } catch (_) {}
  try {
    const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
    const setVerifier = HttpsURLConnection.setHostnameVerifier.overload('javax.net.ssl.HostnameVerifier');
    setVerifier.implementation = function (verifier) {
      let name = null; try { name = String(verifier.getClass().getName()); } catch (_) {}
      send({event: 'network_hostname_verifier', api: 'HttpsURLConnection.setHostnameVerifier', verifier_class: name, result_modified: false});
      return setVerifier.call(this, verifier);
    };
  } catch (_) {}
  try {
    const CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overloads.forEach(function (ov) {
      ov.implementation = function () { send({event: 'network_pinning', api: 'okhttp3.CertificatePinner.check', validation_modified: false}); return ov.apply(this, arguments); };
    });
  } catch (_) {}
});

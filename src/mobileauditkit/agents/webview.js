Java.perform(function () {
  function snapshot(webview, trigger) {
    try {
      const settings = webview.getSettings();
      send({event: 'webview_snapshot', trigger: trigger, javaScriptEnabled: Boolean(settings.getJavaScriptEnabled()), allowFileAccess: Boolean(settings.getAllowFileAccess()), allowContentAccess: Boolean(settings.getAllowContentAccess()), domStorageEnabled: Boolean(settings.getDomStorageEnabled()), content_captured: false});
    } catch (_) {}
  }
  try {
    const WebView = Java.use('android.webkit.WebView');
    const loadUrl = WebView.loadUrl.overload('java.lang.String');
    loadUrl.implementation = function (url) { snapshot(this, 'loadUrl'); return loadUrl.call(this, url); };
    const addInterface = WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String');
    addInterface.implementation = function (object, name) {
      send({event: 'webview_javascript_interface', interface_name: String(name).slice(0, 128), object_methods_captured: false});
      return addInterface.call(this, object, name);
    };
    const debug = WebView.setWebContentsDebuggingEnabled.overload('boolean');
    debug.implementation = function (enabled) { send({event: 'webview_debugging', enabled: Boolean(enabled), result_modified: false}); return debug.call(this, enabled); };
  } catch (_) {}
});

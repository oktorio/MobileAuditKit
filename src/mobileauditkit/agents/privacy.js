Java.perform(function () {
  try {
    const ClipboardManager = Java.use('android.content.ClipboardManager');
    const setPrimaryClip = ClipboardManager.setPrimaryClip.overload('android.content.ClipData');
    setPrimaryClip.implementation = function (clip) {
      const count = clip ? clip.getItemCount() : 0;
      send({event: 'privacy_clipboard_write', item_count: Number(count), content_captured: false});
      return setPrimaryClip.call(this, clip);
    };
  } catch (_) {}
  try {
    const Log = Java.use('android.util.Log');
    ['d', 'i', 'w', 'e', 'v'].forEach(function (name) {
      if (!Log[name]) return;
      Log[name].overloads.forEach(function (ov) {
        ov.implementation = function () { send({event: 'privacy_log_call', level: name, message_captured: false}); return ov.apply(this, arguments); };
      });
    });
  } catch (_) {}
  try {
    const LocationManager = Java.use('android.location.LocationManager');
    LocationManager.requestLocationUpdates.overloads.forEach(function (ov) {
      ov.implementation = function () { send({event: 'privacy_location_request', api: 'LocationManager.requestLocationUpdates', coordinates_captured: false}); return ov.apply(this, arguments); };
    });
  } catch (_) {}
  try {
    const Window = Java.use('android.view.Window');
    const addFlags = Window.addFlags.overload('int');
    addFlags.implementation = function (flags) {
      if ((Number(flags) & 8192) !== 0) send({event: 'privacy_flag_secure', enabled: true});
      return addFlags.call(this, flags);
    };
  } catch (_) {}
});

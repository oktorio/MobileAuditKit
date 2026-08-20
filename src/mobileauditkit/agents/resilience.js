Java.perform(function () {
  try {
    const Debug = Java.use('android.os.Debug');
    const isDebuggerConnected = Debug.isDebuggerConnected.overload();
    isDebuggerConnected.implementation = function () {
      send({event: 'resilience_debug_check', api: 'Debug.isDebuggerConnected', result_modified: false});
      return isDebuggerConnected.call(this);
    };
  } catch (_) {}
  try {
    const File = Java.use('java.io.File');
    const exists = File.exists.overload();
    const artifacts = ['/system/bin/su', '/system/xbin/su', '/sbin/su', '/system/app/Superuser.apk', '/system/app/Magisk.apk'];
    exists.implementation = function () {
      const path = String(this.getAbsolutePath());
      if (artifacts.indexOf(path) >= 0) send({event: 'resilience_root_check', technique: 'root_artifact_file_check', result_modified: false});
      return exists.call(this);
    };
  } catch (_) {}
  try {
    const Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overloads.forEach(function (ov) {
      ov.implementation = function () {
        let text = ''; try { text = String(arguments[0]); } catch (_) {}
        if (text.indexOf('which su') >= 0 || text === 'su') send({event: 'resilience_root_check', technique: 'su_command_check', command_captured: false, result_modified: false});
        return ov.apply(this, arguments);
      };
    });
  } catch (_) {}
});

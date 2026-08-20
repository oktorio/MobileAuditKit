Java.perform(function () {
  function safeName(value) {
    if (value === null || value === undefined) return null;
    const parts = String(value).split('/');
    return parts[parts.length - 1].slice(0, 128);
  }
  try {
    const Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    ['putString', 'putInt', 'putLong', 'putBoolean', 'putFloat'].forEach(function (name) {
      if (!Editor[name]) return;
      Editor[name].overloads.forEach(function (ov) {
        ov.implementation = function () {
          const key = arguments.length > 0 ? safeName(arguments[0]) : null;
          send({event: 'storage_shared_preferences', api: name, key_name: key, value_captured: false});
          return ov.apply(this, arguments);
        };
      });
    });
  } catch (_) {}
  try {
    const ContextWrapper = Java.use('android.content.ContextWrapper');
    const openFileOutput = ContextWrapper.openFileOutput.overload('java.lang.String', 'int');
    openFileOutput.implementation = function (name, mode) {
      send({event: 'storage_file', api: 'openFileOutput', file_name: safeName(name), mode: Number(mode), content_captured: false});
      return openFileOutput.call(this, name, mode);
    };
  } catch (_) {}
  try {
    const SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLiteDatabase.openDatabase.overloads.forEach(function (ov) {
      ov.implementation = function () {
        const path = arguments.length > 0 ? String(arguments[0]) : '';
        send({event: 'storage_database', api: 'SQLiteDatabase.openDatabase', file_name: safeName(path), content_captured: false});
        return ov.apply(this, arguments);
      };
    });
  } catch (_) {}
  try {
    const Environment = Java.use('android.os.Environment');
    const external = Environment.getExternalStorageDirectory.overload();
    external.implementation = function () {
      const result = external.call(this);
      send({event: 'storage_external', api: 'Environment.getExternalStorageDirectory', content_captured: false});
      return result;
    };
  } catch (_) {}
});

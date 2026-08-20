/*
 * MobileAuditKit - cryptography observer
 * Defensive instrumentation only: records algorithm metadata, never keys, IVs,
 * plaintext, ciphertext, credentials, or customer data.
 */
'use strict';

Java.perform(function () {
    const Cipher = Java.use('javax.crypto.Cipher');
    const MessageDigest = Java.use('java.security.MessageDigest');

    function classify(algorithm) {
        const normalized = String(algorithm).toUpperCase();
        if (normalized.indexOf('ECB') !== -1) return 'HIGH';
        if (normalized.indexOf('DES') !== -1 || normalized.indexOf('RC4') !== -1) return 'HIGH';
        if (normalized === 'MD5' || normalized === 'SHA-1' || normalized === 'SHA1') return 'MEDIUM';
        return 'INFO';
    }

    const cipherGetInstance = Cipher.getInstance.overload('java.lang.String');
    cipherGetInstance.implementation = function (transformation) {
        const value = String(transformation);
        send({
            event: 'crypto_algorithm_observed',
            api: 'javax.crypto.Cipher.getInstance',
            algorithm: value,
            severity: classify(value),
            sensitive_data: false
        });
        return cipherGetInstance.call(this, transformation);
    };

    const digestGetInstance = MessageDigest.getInstance.overload('java.lang.String');
    digestGetInstance.implementation = function (algorithm) {
        const value = String(algorithm);
        send({
            event: 'message_digest_observed',
            api: 'java.security.MessageDigest.getInstance',
            algorithm: value,
            severity: classify(value),
            sensitive_data: false
        });
        return digestGetInstance.call(this, algorithm);
    };

    send({event: 'module_ready', module: 'crypto', sensitive_data: false});
});

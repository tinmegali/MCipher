package com.tinmegali.security.mcipher;

import android.os.Build;

/**
 * Holds constant values used by the encryption/decryption
 * process by the {@link Encryptor} and {@link Decryptor} classes.
 */

class Constants {

    /**
     * Cypher transformation.
     * TRANSFORMATION assumes different values, according to the current SDK,
     * for 23+ it uses 'AES/GCM/NoPadding' and for older versions it uses
     * 'RSA/ECB/PKCS1Padding'
     */
    static final String TRANSFORMATION;
    static {
        if (Build.VERSION.SDK_INT >= 23 ) {

            TRANSFORMATION = "AES/GCM/NoPadding";
        } else {
            TRANSFORMATION = "RSA/ECB/PKCS1Padding";
        }
    }

    /**
     * Cypher Transformation to use with the Bouncy Castle provider. This
     * transformation is only used to encrypt and decrypt big chunks of data
     * on older versions of the Android SDK (API < 23).
     */
    static final String TRANSFORMATION_BC = "AES/GCM/NoPadding";

    /**
     * Android's standard {@link java.security.KeyStore} provider.
     */
    static final String ANDROID_KEY_STORE = "AndroidKeyStore";

    /**
     * Shared Preferences name. Prefs are used to store an encrypted SecretKey
     * used at encryption and decryption process on SDK < 23.
     */
    static final String PREFS_NAME = "com.tinmegali.cipher.prefs";


    /**
     * Name to save and retrieve the SecretKey for large files from
     * the Shared Preferences.
     */
    static final String WRAPPED_KEY = "WRAPPED_KEY";

}

package com.tinmegali.security.mcipher;

import android.os.Build;

/**
 * Holds constant values used by the encryption/decryption
 * process by the {@link MEncryptorDefault} and {@link MDecryptorDefault} classes.
 */
public class MCipherConstants {

    // keyStore providers
    final static String KEY_STORE_PROVIDER = "AndroidKeyStore";
    final static String KEY_STORE_PROVIDER_LARGE = "BC";

    // algorithms
    public static final String ALGORITHM_AES = "AES";
    public static final String ALGORITHM_RSA = "RSA";

    // block mode
    public static final String BLOCK_MODE_GCM = "GCM";
    public static final String BLOCK_MODE_CBC = "CBC";

    // paddings
    public static final String PADDING_NO_PADDING = "NoPadding";
    public static final String PADDING_PKCS1 = "PKCS1Padding";
    public static final String PADDING_PKCS7 = "PKCS7Padding";

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

    // TODO testing transformation for really large string
    static final String TRANSFORMATION_LARGE = "AES/CBC/PKCS7Padding";

    /**
     * Cypher Transformation to use with the Bouncy Castle provider. This
     * transformation is only used to encrypt and decrypt big chunks of data
     * on older versions of the Android SDK (API < 23).
     */
    static final String TRANSFORMATION_BC = "AES/GCM/NoPadding";

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

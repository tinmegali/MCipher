package com.tinmegali.security.mcipher;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;
import android.util.Log;

import com.tinmegali.security.mcipher.exceptions.MCipherException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;


/**
 * Utility class with static helper methods to encryption/decryption operations.
 */
public class MCipherUtils {

    private static final String TAG = MCipherUtils.class.getSimpleName();


    /**
     * Clear old keys saved in the {@link MCipherConstants#KEY_STORE_PROVIDER} provider
     * with the given 'alias' and also remove keys with the same name saved in
     * the library SharedPreferences.
     * <p>
     * Notice that the method will only look for keys saved in the default KeyStore,
     * if you're need to remove keys from a customized keystore, use
     * {@link #clearKeysFromKeyStore(KeyStore, String, Context)} method.
     *
     * @param alias   the key's unique id
     * @param context application context
     * @throws MCipherException wrapper exception that encapsulates all possible exceptions
     *                          thrown by the operation.
     */
    public static void clearKeys(
            @NonNull String alias,
            @NonNull Context context
    )
            throws MCipherException {
        Log.w(TAG, "clearKeys");
        try {
            // removing KeyStore entries
            KeyStore store = loadDefaultKeyStore(null);
            removeEntriesFromKeyStore(alias, store);
        } catch (KeyStoreException | IOException
                | NoSuchAlgorithmException | CertificateException e) {
            String msg = String.format(
                    "Something went wrong while trying to remove KeyStore keys." +
                            "\n\t Message: %s" +
                            "\n\t Cause: %s",
                    e.getMessage(), e
            );
            throw new MCipherException(msg, e);
        }
        // removing saved keys
        removeSavedKeys(alias, MCipherConstants.KEY_STORE_PROVIDER, context);
    }

    /**
     * Clear old keys from the provided KeyStore, saved with the given 'alias'
     * and also remove keys with the same name saved in the library SharedPreferences.
     *
     * @param keyStore the KeyStore to remove the keys from.
     * @param alias    the key's unique id
     * @param context  application context
     * @throws MCipherException wrapper exception that encapsulates all possible exceptions
     *                          thrown by the operation.
     */
    public static void clearKeysFromKeyStore(
            KeyStore keyStore, String alias, Context context
    ) throws MCipherException {
        try {
            removeEntriesFromKeyStore(alias, keyStore);
            String providerName = keyStore.getProvider().getName();
            removeSavedKeys(alias, providerName, context);
        } catch (KeyStoreException | IOException
                | NoSuchAlgorithmException | CertificateException e) {
            String msg = String.format(
                    "Something went wrong while trying to remove KeyStore keys." +
                            "\n\t Message: %s" +
                            "\n\t Cause: %s",
                    e.getMessage(), e
            );
            throw new MCipherException(msg, e);
        }
    }

    private static KeyStore loadDefaultKeyStore(
            @Nullable KeyStore.LoadStoreParameter params
    ) throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(
                MCipherConstants.KEY_STORE_PROVIDER
        );
        keyStore.load(params);
        return keyStore;
    }

    private static void removeEntriesFromKeyStore(
            String alias, KeyStore keyStore
    ) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException {
        keyStore.deleteEntry(alias);
        keyStore.deleteEntry(getAliasLarge(alias));
    }

    private static void removeSavedKeys(
            String alias, String keyStoreProvider, Context context
    ) {
        SharedPreferences prefs = context.getSharedPreferences(
                MCipherConstants.PREFS_NAME, Context.MODE_PRIVATE);
        String largeAliasKey = getPrefsKeyToAliasLarge(alias, keyStoreProvider);
        prefs.edit().remove(largeAliasKey).apply();
    }

    static String getAliasLarge(String alias) {
        return alias + "_large";
    }

    private static String getPrefsKeyToAliasLarge(
            String alias, String keyStoreProvider)
    {
        return alias + "_" + keyStoreProvider + "_large";
    }

    static byte[] generateIV() {
        SecureRandom r = new SecureRandom();
        byte[] iv = new byte[12];
        r.nextBytes(iv);
        return iv;
    }

    /**
     * Utility method to encode a byte array to an String
     *
     * @param encoded data to encode to String
     * @return an encoded String
     */
    public static String encodeToStr(byte[] encoded) {
        return new String(encoded, StandardCharsets.UTF_8);
    }

    /**
     * Utility method to decode a String to a byte array
     *
     * @param decoded String to decode to byte array
     * @return a decoded String
     */
    public static byte[] decode(String decoded) {
        return decoded.getBytes(StandardCharsets.UTF_8);
    }

    static byte[] decodeEncrypted(String encryptedStr) {
        return Base64.decode(encryptedStr, Base64.DEFAULT);
    }

    static String encodeEncrypted(byte[] encryptedData) {
        return Base64.encodeToString(encryptedData, Base64.DEFAULT);
    }

}

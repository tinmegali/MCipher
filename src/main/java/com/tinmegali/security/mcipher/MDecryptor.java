package com.tinmegali.security.mcipher;

import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.tinmegali.security.mcipher.exceptions.MDecryptorException;

/**
 * Decryption interface that facilitates the decryption process.
 * Build a {@link MDecryptor} using its builder, the {@link MDecryptorBuilder}.
 * Notice that, for the decryption to have success, the {@link MDecryptor} characteristics,
 * defined during its build, must be compatible with the ones defined for {@link MEncryptor}
 * during its build.
 *
 */
public interface MDecryptor {

    /**
     * Decrypts an encrypted byte array.
     *
     * @param encryptedData a byte array with the encrypted data.
     * @param context the context must only be passed when the method is called from SDK previous to 23.
     *
     * @return a decrypted byte array.
     *
     * @throws MDecryptorException   wraps all possible exception for the decryption
     * process. To access the original exception call {@link MDecryptorException#getCause()}.
     */
    byte[] decrypt(
            @NonNull final byte[] encryptedData,
            @Nullable final Context context
    )
            throws MDecryptorException;

    /**
     * Decrypts an encrypted {@link String}.
     *
     * @param encryptedString a String to be decrypted. It must have been encoded using
     * {@link MCipherUtils#encodeEncrypted(byte[])} method.
     * @param context the context must only be passed when the method is called from SDK previous to 23.
     *
     * @return a decrypted byte array.
     *
     * @throws MDecryptorException   wraps all possible exception for the decryption
     * process. To access the original exception call {@link MDecryptorException#getCause()}.
     */
    byte[] decrypt(
            @NonNull final String encryptedString,
            @Nullable final Context context
    ) throws MDecryptorException;


    /**
     * Decrypts an encrypted {@link String}.
     *
     * @param encryptedString a String to be decrypted. It must have been encoded using
     * {@link MCipherUtils#encodeEncrypted(byte[])} method.
     * @param context the context must only be passed when the method is called from SDK previous to 23.
     *
     * @return a decrypted {@link String}.
     *
     * @throws MDecryptorException   wraps all possible exception for the decryption
     * process. To access the original exception call {@link MDecryptorException#getCause()}.
     */
    String decryptString(
            @NonNull final String encryptedString,
            @Nullable final Context context
    ) throws MDecryptorException;


    /**
     * Get the current Key Alias, defined during build time,
     * used as an unique identifier in the {@link java.security.KeyStore}.
     *
     * @return the current alias of the {@link MDecryptor}.
     */
    String getAlias();

}

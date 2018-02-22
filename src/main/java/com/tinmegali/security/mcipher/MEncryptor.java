package com.tinmegali.security.mcipher;

import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.tinmegali.security.mcipher.exceptions.MEncryptorException;

/**
 * Encryption interface that facilitates the encryption process.
 * Build a {@link MEncryptor} using its builder, the {@link MEncryptorBuilder}.
 *
 */
public interface MEncryptor {

    /**
     * Encrypt a given String.
     * Notice that the encryption particularities
     * will be defined during the {@link MEncryptor} build.
     *
     * @param textToEncrypt a String to be encrypted.
     * @param context the context must only be passed when the method is called from SDK previous to 23.
     * @return  a {@link String} encoded with {@link MCipherUtils#encodeEncrypted(byte[])}
     * helper method, containing the encrypted data.
     *
     * @throws MEncryptorException   a wrapper {@link Exception} that encapsulates all possible exceptions
     * thrown by the encryption process. To get the original {@link Exception}, if it has one,
     * call {@link MEncryptorException#getCause()}.
     * @see MCipherUtils#encodeEncrypted(byte[])
     */
    String encryptString(
            @NonNull final String textToEncrypt,
            @Nullable final Context context )
            throws MEncryptorException;

    /**
     * Encrypts a byte array.
     *
     * Notice that the encryption particularities
     * will be defined during the {@link MEncryptor} build.
     *
     * @param dataToEncrypt byte array to be encrypted.
     * @param context the context must only be passed when the method is called from SDK previous to 23.
     * @return a byte array containing the encrypted data.
     *
     * @throws MEncryptorException   a wrapper {@link Exception} that encapsulates all possible exceptions
     * thrown by the encryption process. To get the original {@link Exception}, if it has one,
     * call {@link MEncryptorException#getCause()}.
     */
    byte[] encrypt(
            @NonNull final byte[] dataToEncrypt,
            @Nullable final Context context )
            throws MEncryptorException;

    /**
     * Encrypts a String, returning an encrypted byte array.
     *
     * Notice that the encryption particularities
     * will be defined during the {@link MEncryptor} build.
     *
     * @param textToEncrypt a String to be encrypted.
     * @param context the context must only be passed when the method is called from SDK previous to 23.
     * @return a byte array containing the encrypted data.
     *
     * @throws MEncryptorException   a wrapper {@link Exception} that encapsulates all possible exceptions
     * thrown by the encryption process. To get the original {@link Exception}, if it has one,
     * call {@link MEncryptorException#getCause()}.
     */
    byte[] encrypt(
            @NonNull final String textToEncrypt,
            @Nullable final Context context )
            throws MEncryptorException;


    /**
     * Get the current Key Alias, defined during build time,
     * used as an unique identifier in the {@link java.security.KeyStore}.
     *
     * @return the current alias of the {@link MEncryptor}.
     */
    String getAlias();

}

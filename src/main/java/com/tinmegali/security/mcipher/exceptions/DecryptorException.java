package com.tinmegali.security.mcipher.exceptions;

import android.content.Context;

import com.tinmegali.security.mcipher.MDecryptor;

import javax.crypto.Cipher;

/**
 * An 'wrapper' {@link Exception} thrown by decryption operations, that wraps it up
 * numerous {@link Exception} that can be thrown by
 * the {@link MDecryptor#decryptData(byte[], Cipher)} and
 * {@link MDecryptor#decryptLargeData(String, byte[], Context)}
 *
 * The {@link DecryptorException#getMessage()} holds an message, containing the
 * original Exception, that you can fetch it with {@link DecryptorException#getCause()}
 */
public class DecryptorException extends Exception {

    public DecryptorException(String message) {
        super(message);
    }

    public DecryptorException(
            String message,
            Exception exception)
    {
        super(message, exception);
    }
}

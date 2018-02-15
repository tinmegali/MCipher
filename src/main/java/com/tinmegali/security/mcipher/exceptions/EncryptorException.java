package com.tinmegali.security.mcipher.exceptions;

import com.tinmegali.security.mcipher.MEncryptor;

import javax.crypto.Cipher;

/**
 * An 'wrapper' {@link Exception} thrown by encryption operations, that wraps it up
 * numerous {@link Exception} that can be thrown by
 * the {@link MEncryptor#encryptData(byte[], Cipher)} method.
 *
 * The {@link EncryptorException#getMessage()} holds an message, containing the
 * original Exception, that you can fetch it with {@link EncryptorException#getCause()}
 */
public class EncryptorException extends Exception {
    public EncryptorException(String message) {
        super(message);
    }
    public EncryptorException(String message, Exception cause ) {
        super( message, cause );
    }
}

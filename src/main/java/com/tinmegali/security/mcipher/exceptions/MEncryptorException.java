package com.tinmegali.security.mcipher.exceptions;

import com.tinmegali.security.mcipher.MEncryptorDefault;

import javax.crypto.Cipher;

/**
 * An 'wrapper' {@link Exception} thrown by encryption operations, that wraps it up
 * numerous {@link Exception} that can be thrown by
 * the {@link MEncryptorDefault#encryptData(byte[], Cipher)} method.
 *
 * The {@link MEncryptorException#getMessage()} holds an message, containing the
 * original Exception, that you can fetch it with {@link MEncryptorException#getCause()}
 */
// TODO update EncryptorException docs
public class MEncryptorException extends Exception {
    public MEncryptorException(String message) {
        super(message);
    }
    public MEncryptorException(String message, Exception cause ) {
        super( message, cause );
    }
}

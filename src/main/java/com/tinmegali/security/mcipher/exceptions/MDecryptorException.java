package com.tinmegali.security.mcipher.exceptions;

import com.tinmegali.security.mcipher.MDecryptorDefault;

import javax.crypto.Cipher;

/**
 * An 'wrapper' {@link Exception} thrown by decryption operations, that wraps it up
 * numerous {@link Exception} that can be thrown by
 * the {@link MDecryptorDefault#decryptData(byte[], Cipher)}
 *
 * The {@link MDecryptorException#getMessage()} holds an message, containing the
 * original Exception, that you can fetch it with {@link MDecryptorException#getCause()}
 */
// TODO update DecryptorException docs
public class MDecryptorException extends Exception {

    public MDecryptorException(String message) {
        super(message);
    }

    public MDecryptorException(
            String message,
            Exception exception)
    {
        super(message, exception);
    }
}

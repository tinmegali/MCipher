package com.tinmegali.security.mcipher.exceptions;

/**
 * com.tinmegali.security.mcipher.exceptions | MCipher
 * __________________________________
 * Created by tinmegali
 * 22/02/2018
 *
 * @see <a href="http://www.tinmegali.com">tinmegali.com</a>
 * @see <a href="http://github.com/tinmegali">github</a>
 * ___________________________________
 */

// TODO document MCipherException
public class MCipherException extends Exception {

    public MCipherException(String message) {
        super(message);
    }

    public MCipherException(String message, Throwable cause) {
        super(message, cause);
    }
}

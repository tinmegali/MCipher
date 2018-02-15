package com.tinmegali.security.mcipher;

import android.util.Base64;

/**
 * Utility class with static helper methods to encryption/decryption operations.
 */

public class MCipherUtils {

    /**
     * Utility method to encode a byte array to an String
     * @param encoded data to encode to String
     * @return an String encoded with Base64
     */
    public static String encodeToStr( byte[] encoded ) {
        return Base64.encodeToString( encoded, Base64.DEFAULT );
    }

    /**
     * Utility method to decode a String to a byte array
     * @param decoded String to decode to byte array
     * @return a String decoded with Base64
     */
    public static byte[] decode( String decoded ) {
        return Base64.decode( decoded, Base64.DEFAULT );
    }

}

package com.tinmegali.security.mcipher;

import android.util.Log;

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

    public static void clearKeys()
            throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException
    {
        Log.w(TAG, "clearKeys");
        KeyStore keyStore = KeyStore.getInstance( KeyStore.getDefaultType() );
        keyStore.load(null);
        keyStore.deleteEntry( Constants.ALIAS_STANDARD_DATA );
        keyStore.deleteEntry( Constants.ALIAS_LARGE_DATA );
    }

    public static byte[] generateIV() {
        SecureRandom r = new SecureRandom();
        byte[] iv = new byte[12];
        r.nextBytes( iv );
        return iv;
    }

    /**
     * Utility method to encode a byte array to an String
     * @param encoded data to encode to String
     * @return an String encoded with Base64
     */
    public static String encodeToStr( byte[] encoded ) {
//        boolean isBase64 = ApacheBase64.isBase64( encoded );
//        if ( isBase64 ) {
//            return Base64.encodeToString(encoded, Base64.NO_WRAP);
//        }
//        else {
//            Log.w(TAG, "Trying to encode byte array that doesn't conform to Base64 standards." +
//                    "\nThe encoding will be done using 'new String( encoded, StandardCharsets.UTF_8 )'.");
            return new String( encoded, StandardCharsets.UTF_8 );
//        }
    }

    /**
     * Utility method to decode a String to a byte array
     * @param decoded String to decode to byte array
     * @return a String decoded with Base64
     */
    public static byte[] decode( String decoded ) {
//        boolean isBase64 = ApacheBase64.isBase64( decoded );
//        if ( isBase64 ) {
//            return Base64.decode(decoded, Base64.NO_WRAP);
//        }
//        else {
//            Log.w(TAG, "Trying to decode String that doesn't conform to Base64 standards." +
//                    "\nThe encoding will be done using 'string.getBytes(UTF8)'");
            return decoded.getBytes(StandardCharsets.UTF_8 );
//        }
    }

}

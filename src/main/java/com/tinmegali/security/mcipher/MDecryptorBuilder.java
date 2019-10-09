package com.tinmegali.security.mcipher;

import android.util.Log;

import com.tinmegali.security.mcipher.exceptions.MDecryptorException;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * {@link MDecryptor} builder.
 */
public class MDecryptorBuilder {

    private static final String TAG = MDecryptorBuilder.class.getSimpleName();
    private static MDecryptorDefault decryptor;

    /**
     * Builds the {@link MDecryptor} with a initialized {@link java.security.KeyStore}.
     *
     * @return an initialized {@link MDecryptor}.
     * @throws MDecryptorException thrown if it finds some problem during the initialization.
     */
    public static MDecryptor build( final String defaultAlias ) throws MDecryptorException {
        if (decryptor == null) {
            Log.d(TAG, "creating new 'decryptor' instance: " + defaultAlias);
            decryptor = new MDecryptorDefault( defaultAlias );
            try {
                decryptor.initKeyStore();
                return decryptor;
            } catch (CertificateException | NoSuchAlgorithmException
                    | IOException | KeyStoreException e) {
                String errorMsg =
                        String.format("Something went wrong while initiating the KeyStore." +
                                "%n\t%s", e.getMessage());
                throw new MDecryptorException(errorMsg, e);
            }
        } else {
            Log.d(TAG, "returning decryptor instance: alias: " + decryptor.getAlias());
            return decryptor;
        }
    }

    // TODO turn 'ON' the MDecryptorBuilder options
//    public MDecryptorBuilder transformation(
//            String transformation,
//            AlgorithmParameterSpec spec )
//    {
//        decryptor.setTRANSFORMATION( transformation );
//        decryptor.setSTANDARD_SPECS( spec );
//        return this;
//    }
//
//    public MDecryptorBuilder protectionParams(
//            KeyStore.ProtectionParameter protectionParameter
//    ) {
//        decryptor.setPROTECTION_PARAMS( protectionParameter );
//        return this;
//    }
//
//    public MDecryptorBuilder transformationLarge(String transformation ) {
//        decryptor.setTRANSFORMATION_LARGE( transformation );
//        return this;
//    }
    
}

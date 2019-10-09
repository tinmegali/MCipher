package com.tinmegali.security.mcipher;

import com.tinmegali.security.mcipher.exceptions.MDecryptorException;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * {@link MDecryptor} builder.
 */
public class MDecryptorBuilder {

    private static final String TAG = MEncryptorBuilder.class.getSimpleName();
    private static MEncryptorDefault encryptor;

    /**
     * Builds the {@link MDecryptor} with a initialized {@link java.security.KeyStore}.
     *
     * @return an initialized {@link MDecryptor}.
     * @throws MDecryptorException thrown if it finds some problem during the initialization.
     */
    public static MEncryptor build( final String defaultAlias ) throws MEncryptorException {
        Log.d(TAG, "build: " + defaultAlias);
        if (encryptor == null) {
            Log.d(TAG, "creating new 'encryptor' instance:" + defaultAlias);
            encryptor = new MEncryptorDefault(defaultAlias);
            try {
                encryptor.initKeyStore();
                return encryptor;
            } catch (CertificateException | KeyStoreException
                    | IOException | NoSuchAlgorithmException e) {
                String errorMsg =
                        String.format("Something went wrong while initiating the KeyStore." +
                                "%n\t%s", e.getMessage());
                throw new MEncryptorException(errorMsg, e);
            }
        } else {
            Log.d(TAG, "returning 'encryptor' instance");
            return encryptor;
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

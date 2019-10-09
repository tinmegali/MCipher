package com.tinmegali.security.mcipher;

import android.util.Log;

import com.tinmegali.security.mcipher.exceptions.MEncryptorException;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * {@link MEncryptor} builder.
 */
public class MEncryptorBuilder {

    private static final String TAG = MEncryptorBuilder.class.getSimpleName();
    private static MEncryptorDefault encryptor;

    /**
     * Builds the {@link MEncryptor} with a initialized {@link java.security.KeyStore}.
     *
     * @return an initialized {@link MEncryptor}.
     *
     * @throws MEncryptorException thrown if it finds some problem during the initialization.
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
    // TODO turn 'ON' the MEncryptorBuilder options

//    public MEncryptorBuilder keyStoreProvider(String provider ) {
//        encryptor.setKEYSTORE_PROVIDER( provider );
//        return this;
//    }
//
//    public MEncryptorBuilder keyStoreParams(KeyStore.LoadStoreParameter params ) {
//        encryptor.setKEYSTORE_PARAMS( params );
//        return this;
//    }
//
//    public MEncryptorBuilder transformation(
//            String transformation,
//            AlgorithmParameterSpec spec )
//    {
//        encryptor.setTRANSFORMATION( transformation );
//        encryptor.setCIPHER_SPECS( spec );
//        return this;
//    }
//
//    public MEncryptorBuilder protectionParams(
//            KeyStore.ProtectionParameter protectionParameter
//    ) {
//        encryptor.setPROTECTION_PARAMS( protectionParameter );
//        return this;
//    }
//
//    public MEncryptorBuilder password(char[] password ) {
//        encryptor.setPASSWORD( password );
//        return this;
//    }
//
//    public MEncryptorBuilder secretKeyAlgorithm(String algorithm ) {
//        encryptor.setSECRET_KEY_ALGORITHM( algorithm );
//        return this;
//    }
//
//    public MEncryptorBuilder secretKeyBlockModes(String... modes ) {
//        encryptor.setSECRET_KEY_BLOCK_MODES( modes );
//        return this;
//    }
//
//    public MEncryptorBuilder secretKeyPaddings(String... paddings ) {
//        encryptor.setSECRET_KEY_PADDINGS( paddings );
//        return this;
//    }
//
//    public MEncryptorBuilder secretKeySpecs(KeyGenParameterSpec specs ) {
//        encryptor.setSECRET_KEY_SPECS( specs );
//        return this;
//    }
//
//    public MEncryptorBuilder certificateDate(Date startDate, Date endDate ) {
//        encryptor.setCERTIFICATE_DATE( startDate, endDate );
//        return this;
//    }
//
//    public MEncryptorBuilder certificateSubject(X500Principal subject ) {
//        encryptor.setCERTIFICATE_SUBJECT( subject );
//        return this;
//    }
//
//    public MEncryptorBuilder keyPairGeneratorSpecs(KeyPairGeneratorSpec spec ) {
//        encryptor.setKEY_PAIR_GENERATOR_SPECS( spec );
//        return this;
//    }
    
}

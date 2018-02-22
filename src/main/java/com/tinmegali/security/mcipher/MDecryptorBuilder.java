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

    private MDecryptorDefault decryptor;

    /**
     * Constructs a new {@link MDecryptor} builder.
     *
     * @param defaultAlias the unique identifier used by all operation done in the {@link java.security.KeyStore}.
     *                     A good alias would be your package name plus an identifier, like
     *                     'my.package.name.key'. Notice that the alias must the exactly the same
     *                     used during the encryption process.
     *
     * @throws MDecryptorException thrown if it finds some problem during the instantiation.
     */
    public MDecryptorBuilder( final String defaultAlias ) throws MDecryptorException {
        decryptor = new MDecryptorDefault( defaultAlias );
    }

    /**
     * Builds the {@link MDecryptor} with a initialized {@link java.security.KeyStore}.
     *
     * @return an initialized {@link MDecryptor}.
     * @throws MDecryptorException thrown if it finds some problem during the initialization.
     */
    public MDecryptor build() throws MDecryptorException {
        try {
            decryptor.initKeyStore();
            return decryptor;
        } catch (CertificateException | NoSuchAlgorithmException
                | IOException | KeyStoreException e) {
            String errorMsg =
                    String.format("Something went wrong while initiating the KeyStore." +
                            "%n\t%s", e.getMessage());
            throw new MDecryptorException( errorMsg, e );
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

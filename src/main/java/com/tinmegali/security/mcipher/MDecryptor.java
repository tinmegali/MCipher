package com.tinmegali.security.mcipher;

import android.content.Context;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.util.Log;

import com.tinmegali.security.mcipher.exceptions.DecryptorException;
import com.tinmegali.security.mcipher.exceptions.KeyWrapperException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * Utility Class to Decrypt a byte[] that was encrypted with {@link MEncryptor}.
 */

@SuppressWarnings("JavaDoc")
public class MDecryptor {

    private static final String TAG = MDecryptor.class.getSimpleName();

    private final String ALIAS_STANDARD;
    private final String ALIAS_LARGE;
    private String TRANSFORMATION = Constants.TRANSFORMATION;
    private String TRANSFORMATION_LARGE = Constants.TRANSFORMATION_BC;
    private String PROVIDER_STANDARD = Constants.PROVIDER;
    private String PROVIDER_LARGE = Constants.PROVIDER_LARGE;
    private boolean transformationStandard = true;
    private AlgorithmParameterSpec STANDARD_SPECS;
    private KeyStore.ProtectionParameter STANDARD_PROTECTION_PARAMS = null;

    private KeyStore keyStore;

    protected MDecryptor( final String alias ) throws DecryptorException
    {
        ALIAS_STANDARD = alias;
        ALIAS_LARGE = ALIAS_STANDARD + "_large";
        try {
            initKeyStore();
        } catch (CertificateException | NoSuchAlgorithmException
                | IOException | KeyStoreException e) {
            String errorMsg =
                    String.format("Something went wrong while initiating the KeyStore." +
                            "%n\t%s", e.getMessage());
            Log.e(TAG, errorMsg);
            throw new DecryptorException( errorMsg, e );
        }
    }

    /**
     * Initializes the {@link KeyStore} used in the decryption process. It loads
     * Android's standard KeyStore provider, 'AndroidKeyStore. This method is
     * called by the constructor during the initialization process.
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws KeyStoreException
     */
    @SuppressWarnings("JavaDoc")
    protected void initKeyStore()
            throws CertificateException, NoSuchAlgorithmException,
            IOException, KeyStoreException
    {
        Log.i(TAG, "initKeyStore()");
        keyStore = KeyStore.getInstance( Constants.PROVIDER);
        keyStore.load( null );
    }

    /**
     * Decrypt a given byte array, returning a decrypted {@link String}.
     *
     * @param encryptedData a byte array with the encrypted data. If the
     *                      encryption process used the AES algorithm,
     *                      the data must contain the Vector IV. In fact,
     *                      the encrypted data must by a serializable {@link MEncryptedObject},
     *                      containing the vector iv information.
     * @return a decrypted String.
     * @throws DecryptorException   wraps all possible exception for the decryption
     * process. To access the original exception call {@link DecryptorException#getCause()}.
     */
    @NonNull
    public byte[] decrypt(
            @NonNull final byte[] encryptedData,
            @Nullable final Context context
    )
            throws DecryptorException
    {
        Log.i(TAG, "decrypt");
        try {
            MEncryptedObject encryptedObject =
                    MEncryptedObject.getEncryptedObject( encryptedData );

            if ( encryptedObject.isLarge() ) return decryptLargeData( encryptedData, context );

            // notice that CipherIV will be null for API 18 < 23
            final Cipher cipher = getCipher(ALIAS_STANDARD, encryptedObject.getCypherIV());
            return decryptData( encryptedObject.getData(), cipher);

        }
        catch ( NoSuchProviderException | UnrecoverableEntryException | KeyStoreException
                | NoSuchAlgorithmException | InvalidKeyException
                | NoSuchPaddingException | InvalidAlgorithmParameterException
                | BadPaddingException
                | IllegalBlockSizeException | IOException | ClassNotFoundException e) {
            String errorMsg = String.format(
                    "An error occurred while decrypting data." +
                            "%n\t Exception: [%s]" +
                            "%n\t Cause: %s",
                    e.getClass().getSimpleName(), e );
            Log.e(TAG, errorMsg);
            throw new DecryptorException( errorMsg, e );
        }
    }

    /**
     * Uses AES algorithm to decrypt large chunks of data. If the method
     * is called from SDK 23+, it will make a standard decryption operation,
     * calling {@link MDecryptor#decrypt(byte[], Context)}. If the method
     * id called from SDK < 23, it will make the decryption using
     * an AES algorithm, from the Bouncy Castle provider calling
     * {@link MDecryptor#wrapperCipher(String, Context, byte[])} to get the cipher and
     * then calling {@link MDecryptor#decryptData(byte[], Cipher)} providing the cipher.
     * @param encryptedData encrypted data
     * @param context current Context.
     * @return a byte array with the decrypted data.
     * @throws DecryptorException for any errors.
     */
    @NonNull
    public byte[] decryptLargeData(
            final byte[] encryptedData,
            final Context context
    ) throws DecryptorException {
        byte[] decrypted;
        try {
            if ( Build.VERSION.SDK_INT >= 23 ) {
                decrypted = decrypt( encryptedData, context );
            } else {
                MEncryptedObject obj = MEncryptedObject.getEncryptedObject( encryptedData );
                Cipher cipher = wrapperCipher(ALIAS_LARGE, context, obj.getCypherIV());
                decrypted = decryptData( obj.getData(), cipher );
            }
            return decrypted;

        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | UnrecoverableEntryException | InvalidKeyException
                | NoSuchProviderException | InvalidAlgorithmParameterException
                | IllegalBlockSizeException | KeyStoreException
                | BadPaddingException | KeyWrapperException
                | IOException | ClassNotFoundException e)
        {

            String errorMsg = String.format(
                    "And error occurred while decrypting data." +
                            "%n\t Exception: [%s]" +
                            "%n\t Cause: %s",
                    e.getClass().getSimpleName(), e);
            Log.e(TAG, errorMsg);
            throw new DecryptorException( errorMsg, e );
        }
    }

    /**
     * Decrypt a given byte array using the provided {@link Cipher}
     *
     * @param ecryptedData byte array with the encrypted data
     * @param cipher    Cipher to be used in the decryption operation.
     *
     * @return  A byte array with the decrypted data.
     * @throws UnsupportedEncodingException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws UnrecoverableEntryException
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     */
    @NonNull
    protected byte[] decryptData( @NonNull final byte[] ecryptedData,
                                @NonNull final Cipher cipher)
            throws UnsupportedEncodingException, BadPaddingException,
            IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            UnrecoverableEntryException, KeyStoreException, NoSuchProviderException
    {
//        Log.i(TAG, "decryptData");

        return cipher.doFinal( ecryptedData );
    }

    /**
     * Load a {@link Cipher} according to Android's SDK in use.
     * For API 23+, the Cipher uses the transformation 'AES/GCM/NoPadding'
     * and for API < 23 it uses 'RSA/ECB/PKCS1Padding'.
     * The {@link Cipher} also takes into consideration the current SDK
     * to define if it will need a {@link SecretKey} for SDK 23+ or a {@link KeyPair}
     * on older systems.
     *
     * @param alias an unique identifier used to load a {@link SecretKey}
     *              ot a {@link KeyPair} previously stored in the {@link KeyStore}.
     * @param encryptionIV the vector IV used during at the encryption process. Only used
     *                     for encryption made with algorithm 'AES' (SDK 23+).
     * @return  a {@link Cipher} loaded with {@link Cipher#DECRYPT_MODE}
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws UnrecoverableEntryException
     * @throws KeyStoreException
     */
    @NonNull
    protected Cipher getCipher(
            @NonNull String alias,
            @Nullable byte[] encryptionIV
    ) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException,
            UnrecoverableEntryException, KeyStoreException,
            DecryptorException, NoSuchProviderException
    {
        final Cipher cipher = Cipher.getInstance( TRANSFORMATION );

        if (Build.VERSION.SDK_INT >= 23 ) {
            AlgorithmParameterSpec specs;
            if ( isTransformationStandard() ) {
                specs = new GCMParameterSpec(128, encryptionIV);
            } else {
                specs = this.STANDARD_SPECS;
            }
            cipher.init(Cipher.DECRYPT_MODE, getSecretKey(alias), specs);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, getKeyPair(alias).getPrivate() );
        }
        return cipher;
    }

    /**
     * Recovers a {@link SecretKey} that was saved on the {@link KeyStore}
     * with the given 'alias'.
     *
     * This method is the API's standard for decryption for Android SDK 23+.
     * For SDK < 23, use {@link MDecryptor#getKeyPair(String)}.
     *
     * @param alias a unique id that was used to save the SecretKey in the KeyStore.
     * @return  s SecretKey to be used in the decryption process.
     * @throws UnrecoverableEntryException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    protected SecretKey getSecretKey( String alias )
            throws UnrecoverableEntryException, NoSuchAlgorithmException,
            KeyStoreException
    {
//        Log.i(TAG, String.format("getSecretKey( %s )", alias));

        KeyStore.SecretKeyEntry entry =
                ((KeyStore.SecretKeyEntry)
                        keyStore.getEntry(alias, STANDARD_PROTECTION_PARAMS ));
        return entry.getSecretKey();
    }

    /**
     * Recovers a {@link KeyPair} composed of a public and a secret key.
     * The KeyPair was saved on the {@link KeyStore} with the given 'alias'.
     *
     * Keep in mind that {@link KeyPair#getPublic()} should be use
     * for encryption and {@link KeyPair#getPrivate()} for decryption.
     *
     * This method is the API's standard for decryption for Android SDK < 23.
     * For SDK 23+, use {@link MDecryptor#getSecretKey(String)}.
     *
     * @param alias a unique id that was used to save the SecretKey in the KeyStore.
     * @return  a KeyPair containing a public and a secret key.
     * @throws UnrecoverableEntryException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    protected KeyPair getKeyPair( String alias )
            throws UnrecoverableEntryException, NoSuchAlgorithmException,
            KeyStoreException, DecryptorException
    {
//        Log.i(TAG, String.format("getSecretKeyAPI18( %s )", alias));

        PrivateKey privateKey = (PrivateKey) keyStore.getKey( alias, null );
        // public key is taken form Certificate
        Certificate certificate = keyStore.getCertificate( alias );

        if ( privateKey != null && certificate!= null ) {
            PublicKey publicKey = certificate.getPublicKey();
            return new KeyPair(publicKey, privateKey);
        } else {
            throw new DecryptorException(
                    String.format("Wasn't possible to recover KeyPair [%s] form KeyStore",
                            alias));
        }

    }

    /**
     * Generate a {@link Cipher} to be used with the
     * {@link MDecryptor#decryptLargeData(byte[], Context)} when
     * called from SDK < 23.
     * @param alias unique identifier tight to secret key.
     * @param context current Context.
     * @return a {@link Cipher} using {@link Constants#TRANSFORMATION_BC} as its transformation
     * and set to DECRYPT_MODE.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws UnrecoverableEntryException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     * @throws IllegalBlockSizeException
     * @throws DecryptorException
     * @throws KeyWrapperException
     */
    protected Cipher wrapperCipher(
            @NonNull final String alias,
            final @NonNull Context context,
            final byte[] cipherIV
    )
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, UnrecoverableEntryException,
            InvalidAlgorithmParameterException, NoSuchProviderException,
            KeyStoreException, IllegalBlockSizeException, DecryptorException,
            KeyWrapperException, IOException, ClassNotFoundException
    {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION_LARGE);
        SecretKey bcKey = getUnwrappedBCKey( alias, context );
        IvParameterSpec specs = new IvParameterSpec( cipherIV );
        cipher.init( Cipher.DECRYPT_MODE, bcKey, specs );
        return cipher;
    }

    /**
     * Load a generated a Bouncy Castle secret key with
     * {@link MKeyWrapper#loadWrappedBCKey(Context, Key, String)}.
     * If the key wasn't already generated and stored, it will throw
     * a {@link KeyWrapperException}.
     * @param alias unique identifier tight to standard secret key.
     * @param context current Context.
     * @return a Bouncy Castle secret key.
     * @throws NoSuchPaddingException
     * @throws UnrecoverableEntryException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws DecryptorException
     * @throws KeyWrapperException
     */
    protected SecretKey getUnwrappedBCKey(
            @NonNull String alias, @NonNull Context context
    )
            throws NoSuchPaddingException, UnrecoverableEntryException,
            NoSuchAlgorithmException, KeyStoreException, InvalidKeyException,
            NoSuchProviderException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, DecryptorException, KeyWrapperException,
            IOException, ClassNotFoundException
    {

        Key key;

        if ( Build.VERSION.SDK_INT < 23 ) {
            key = getKeyPair( alias ).getPrivate();
            MKeyWrapper keyWrapper = new MKeyWrapper();
            return keyWrapper.loadWrappedBCKey( context, key, ALIAS_LARGE );
        }
        throw new DecryptorException("SDK 23+ doesn't rely on BCKeys");
    }

    private void setTRANSFORMATION( String TRANSFORMATION ) {
        this.TRANSFORMATION = TRANSFORMATION;
        this.transformationStandard = false;
    }

    private void setTRANSFORMATION_LARGE(String TRANSFORMATION_LARGE) {
        this.TRANSFORMATION_LARGE = TRANSFORMATION_LARGE;
    }

    public boolean isTransformationStandard() {
        return transformationStandard;
    }

    public void setSTANDARD_SPECS(AlgorithmParameterSpec STANDARD_SPECS) {
        this.STANDARD_SPECS = STANDARD_SPECS;
    }

    public void setSTANDARD_PROTECTION_PARAMS(
            KeyStore.ProtectionParameter STANDARD_PROTECTION_PARAMS
    ) {
        this.STANDARD_PROTECTION_PARAMS = STANDARD_PROTECTION_PARAMS;
    }

    public static class Builder {

        private MDecryptor decryptor;

        public Builder( final String defaultAlias ) throws DecryptorException {
            decryptor = new MDecryptor( defaultAlias );
        }

        public MDecryptor build() {
            return decryptor;
        }

        public Builder transformation(
                String transformation,
                AlgorithmParameterSpec spec )
        {
            decryptor.setTRANSFORMATION( transformation );
            decryptor.setSTANDARD_SPECS( spec );
            return this;
        }

        public Builder protectionParams(
                KeyStore.ProtectionParameter protectionParameter
        ) {
            decryptor.setSTANDARD_PROTECTION_PARAMS( protectionParameter );
            return this;
        }

        public Builder transformationLarge( String transformation ) {
            decryptor.setTRANSFORMATION_LARGE( transformation );
            return this;
        }

    }


}

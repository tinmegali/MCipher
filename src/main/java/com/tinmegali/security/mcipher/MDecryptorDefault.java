package com.tinmegali.security.mcipher;

import android.content.Context;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.util.Log;

import com.tinmegali.security.mcipher.exceptions.MDecryptorException;
import com.tinmegali.security.mcipher.exceptions.MKeyWrapperException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * Decrypts data using Android's native libraries.
 * Compatible with SDK 19+.
 *
 * The decryption process will adapt itself to the current SDK, using the
 * same logic adopted in the {@link MEncryptorDefault}.
 *
 * For any decryption process to work correctly, the {@link MDecryptor}
 * configuration must be compatible with the {@link MEncryptor} configuration
 * used during the encryption process.
 *
 * Use the class builder {@link MDecryptorBuilder} to instantiate and
 * configure a {@link MDecryptor} object.
 */

@SuppressWarnings("JavaDoc")
public class MDecryptorDefault implements MDecryptor {

    private static final String TAG = MDecryptorDefault.class.getSimpleName();

    private final String ALIAS;
    private final String ALIAS_LARGE;

    private String TRANSFORMATION = MCipherConstants.TRANSFORMATION;
    private String TRANSFORMATION_LARGE = MCipherConstants.TRANSFORMATION_BC;

    private String PROVIDER = MCipherConstants.KEY_STORE_PROVIDER;
    private String PROVIDER_LARGE = MCipherConstants.KEY_STORE_PROVIDER_LARGE;

    private boolean transformationStandard = true;
    private AlgorithmParameterSpec SPECS;
    private KeyStore.ProtectionParameter PROTECTION_PARAMS = null;

    private KeyStore keyStore;

    protected MDecryptorDefault(final String alias ) throws MDecryptorException
    {
        ALIAS = alias;
        ALIAS_LARGE = ALIAS + "_large";
    }

    /**
     * Initializes the {@link KeyStore} used in the decryption process.
     *
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
//        Log.i(TAG, "initKeyStore()");
        keyStore = KeyStore.getInstance( PROVIDER );
        keyStore.load( null );
    }

    /**
     * Decrypt a given byte array, returning a byte array.
     *
     * Checks if the encrypted data is considered 'large',
     * and calls {@link #decryptLargeData(byte[], Context)} if necessary.
     *
     * Notice that for the method to work, the {@link MDecryptor} configuration
     * must be compatible with the configuration used on the {@link MEncryptor}
     * during the encryption process.
     *
     * @param encryptedData a byte array with the encrypted data.
     * @param context the context must only be passed when the method is called from SDK previous to 23.
     *
     * @return a decrypted byte array.
     * @throws MDecryptorException   wraps all possible exception for the decryption
     * process. To access the original exception call {@link MDecryptorException#getCause()}.
     *
     * @see #getCipher(String, byte[])
     * @see #decryptData(byte[], Cipher)
     * @see #decryptLargeData(byte[], Context)
     */
    @Override
    public byte[] decrypt(
            @NonNull final byte[] encryptedData,
            @Nullable final Context context
    )
            throws MDecryptorException
    {
        Log.i(TAG, "decrypt");
        try {
            MEncryptedObject encryptedObject =
                    MEncryptedObject.getEncryptedObject( encryptedData );

            // verify if the data was encrypted using large data encryption
            if ( encryptedObject.isLarge() )
                return decryptLargeData( encryptedData, context );

            // notice that CipherIV will be null for API 18 < 23
            final Cipher cipher = getCipher(ALIAS, encryptedObject.getCypherIV());
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
            throw new MDecryptorException( errorMsg, e );
        }
    }

    /**
     * Decrypts a given String, returning a decrypted byte array. The encrypted
     * String must have been encoded with {@link MCipherUtils#encodeEncrypted(byte[])}
     * or be obtained by {@link MEncryptor#encryptString(String, Context)} method.
     *
     * The decryption process is done by {@link #decrypt(byte[], Context)}.
     *
     * Notice that for the method to work, the {@link MDecryptor} configuration
     * must be compatible with the configuration used on the {@link MEncryptor}
     * during the encryption process.
     *
     * @param encryptedString a String to be decrypted. It must have been encoded using
     * {@link MCipherUtils#encodeEncrypted(byte[])} method.
     * @param context the context must only be passed when the method is called from SDK previous to 23.
     *
     * @return a decrypted byte array.
     * @throws MDecryptorException   wraps all possible exception for the decryption
     * process. To access the original exception call {@link MDecryptorException#getCause()}.
     *
     * @see MCipherUtils#decodeEncrypted(String)
     * @see #decrypt(byte[], Context)
     */
    @Override
    public byte[] decrypt(
            @NonNull String encryptedString,
            @Nullable Context context
    ) throws MDecryptorException
    {

        byte[] encrypted = MCipherUtils.decodeEncrypted( encryptedString );
        return decrypt( encrypted, context );
    }

    /**
     * Decrypts a given String, returning a decrypted String. The encrypted
     * String must have been encoded with {@link MCipherUtils#encodeEncrypted(byte[])}
     * or be obtained by {@link MEncryptor#encryptString(String, Context)} method.
     *
     * The decryption process is done by {@link #decrypt(byte[], Context)}.
     *
     * Notice that for the method to work, the {@link MDecryptor} configuration
     * must be compatible with the configuration used on the {@link MEncryptor}
     * during the encryption process.
     *
     * @param encryptedString a String to be decrypted. It must have been encoded using
     * {@link MCipherUtils#encodeEncrypted(byte[])} method.
     * @param context the context must only be passed when the method is called from SDK previous to 23.
     *
     * @return a decrypted String
     * @throws MDecryptorException   wraps all possible exception for the decryption
     * process. To access the original exception call {@link MDecryptorException#getCause()}.@throws MDecryptorException
     *
     * @see MCipherUtils#decodeEncrypted(String)
     * @see MCipherUtils#encodeToStr(byte[])
     * @see #decrypt(byte[], Context)
     */
    @Override
    public String decryptString(@NonNull String encryptedString, @Nullable Context context) throws MDecryptorException {
        byte[] encrypted = MCipherUtils.decodeEncrypted( encryptedString );
        byte[] decrypted = decrypt( encrypted, context );
        return MCipherUtils.encodeToStr( decrypted );
    }

    /**
     * Decrypts large chunks of data.
     *
     * For SDK previous to 23, it loads a {@link Cipher} used to wrap a SecretKey used during the
     * encryption process and then uses this Cipher to decrypt with {@link #decryptWithStream(byte[], Cipher)}.
     *
     * For SDK 23+, call {@link #decryptWithStream(byte[], Cipher)}.
     *
     * The encrypted data must contain the vector IV used during encryption, that is
     * obtained by a deserialization of a {@link MEncryptedObject}.
     *
     * @param encryptedData encrypted data
     * @param context current Context.
     * @return a byte array with the decrypted data.
     * @throws MDecryptorException for any errors.
     *
     * @see MEncryptedObject#getEncryptedObject(byte[])
     * @see MEncryptedObject#getCypherIV()
     * @see #wrapperCipher(String, Context, byte[])
     * @see #decryptWithStream(byte[], Cipher)
     */
    @NonNull
    protected byte[] decryptLargeData(
            final byte[] encryptedData,
            final Context context
    ) throws MDecryptorException {
        try {
            MEncryptedObject obj = MEncryptedObject.getEncryptedObject( encryptedData );
            if ( Build.VERSION.SDK_INT >= 23 ) {
                // SDK 23+
                final Cipher cipher = getCipher(ALIAS, obj.getCypherIV());
                return decryptWithStream( obj.getData(), cipher);
            } else {
                // SDK 19|22
                Cipher cipher = wrapperCipher(ALIAS_LARGE, context, obj.getCypherIV());
//                decrypted = decryptData( obj.getData(), cipher );
                return decryptWithStream( obj.getData(), cipher );
            }

        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | UnrecoverableEntryException | InvalidKeyException
                | NoSuchProviderException | InvalidAlgorithmParameterException
                | IllegalBlockSizeException | KeyStoreException
                | MKeyWrapperException | IOException | ClassNotFoundException e)
        {

            String errorMsg = String.format(
                    "And error occurred while decrypting data." +
                            "%n\t Exception: [%s]" +
                            "%n\t Cause: %s",
                    e.getClass().getSimpleName(), e);
            Log.e(TAG, errorMsg);
            throw new MDecryptorException( errorMsg, e );
        }
    }

    /**
     * Decrypt large chunks of data using {@link CipherInputStream}.
     *
     * @param toDecrypt data to decrypt
     * @param cipher cipher used in the decryption
     * @return a decrypted byte array
     * @throws IOException
     */
    protected byte[] decryptWithStream(byte[] toDecrypt, Cipher cipher )
            throws IOException
    {

        InputStream in = new ByteArrayInputStream( toDecrypt );
        CipherInputStream cipherIn = new CipherInputStream( in, cipher );

        // making the encryption
        ArrayList<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherIn.read()) != -1) {
            values.add((byte) nextByte);
        }

        // recovering the encrypted data
        byte[] encryptedData = new byte[values.size()];
        for (int i = 0; i < encryptedData.length; i++) {
            encryptedData[i] = values.get(i);
        }

        return encryptedData;

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
     *
     * By default, in API 23+, the Cipher uses the transformation 'AES/GCM/NoPadding'
     * and for API < 23 it uses 'RSA/ECB/PKCS1Padding'.
     *
     * The {@link Cipher} also takes into consideration the current SDK
     * to define if it will need a {@link SecretKey} for SDK 23+ or a {@link KeyPair}'s
     * {@link PrivateKey} on older systems.
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
     *
     * @see #getSecretKey(String)
     * @see #getKeyPair(String)
     */
    @NonNull
    protected Cipher getCipher(
            @NonNull String alias,
            @Nullable byte[] encryptionIV
    ) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException,
            UnrecoverableEntryException, KeyStoreException,
            MDecryptorException, NoSuchProviderException
    {
        final Cipher cipher = Cipher.getInstance( TRANSFORMATION );

        if (Build.VERSION.SDK_INT >= 23 ) {
            AlgorithmParameterSpec specs;
            if ( isTransformationStandard() ) {
                specs = new GCMParameterSpec(128, encryptionIV);
            } else {
                specs = this.SPECS;
            }
            SecretKey secretKey = getSecretKey(alias);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, specs);
        } else {
            // TODO give the possibility to use randomness and different parameters
            PrivateKey privateKey = getKeyPair( alias ).getPrivate();
            cipher.init(Cipher.DECRYPT_MODE, privateKey );
        }
        return cipher;
    }

    /**
     * Recovers a {@link SecretKey} that was used during the encryption process.
     *
     * This method is the aimed for Android SDK 23+.
     * For SDK < 23, use {@link MDecryptorDefault#getKeyPair(String)}.
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
                        keyStore.getEntry(alias, PROTECTION_PARAMS));
        return entry.getSecretKey();
    }

    /**
     * Recovers a {@link KeyPair} composed of a {@link PublicKey} and a {@link SecretKey}.
     * The KeyPair was used during the encryption process.
     *
     * Keep in mind that {@link KeyPair#getPublic()} should be use
     * for encryption and {@link KeyPair#getPrivate()} for decryption.
     *
     * This method is aimed for Android SDK < 23.
     * For SDK 23+, use {@link MDecryptorDefault#getSecretKey(String)}.
     *
     * @param alias a unique id that was used to save the SecretKey in the KeyStore.
     * @return  a KeyPair containing a public and a secret key.
     * @throws UnrecoverableEntryException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    protected KeyPair getKeyPair( String alias )
            throws UnrecoverableEntryException, NoSuchAlgorithmException,
            KeyStoreException, MDecryptorException
    {
//        Log.i(TAG, String.format("getSecretKeyAPI18( %s )", alias));

        // TODO give the possibility of a password protection
        PrivateKey privateKey = (PrivateKey) keyStore.getKey( alias, null );
        // public key is taken form Certificate
        Certificate certificate = keyStore.getCertificate( alias );

        if ( privateKey != null && certificate!= null ) {
            PublicKey publicKey = certificate.getPublicKey();
            return new KeyPair(publicKey, privateKey);
        } else {
            throw new MDecryptorException(
                    String.format("Wasn't possible to recover KeyPair [%s] form KeyStore",
                            alias));
        }

    }

    /**
     * Generate a {@link Cipher} to be used with the
     * {@link MDecryptorDefault#decryptLargeData(byte[], Context)}.
     *
     * It 'unWraps' a {@link SecretKey} used to encrypt large chunks
     * of data in SDKs previous to 23, and uses this key to generate the Cipher.
     *
     * @param alias unique identifier tight to secret key.
     * @param context current Context.
     * @param cipherIV the vector IV used during encryption.
     * @return a {@link Cipher} to be used in the decryption process of large chunks of data
     * in older SDKs.
     *
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws UnrecoverableEntryException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     * @throws IllegalBlockSizeException
     * @throws MDecryptorException
     * @throws MKeyWrapperException
     *
     * @see #getUnwrappedLargeKey(String, Context)
     */
    protected Cipher wrapperCipher(
            @NonNull final String alias,
            final @NonNull Context context,
            final byte[] cipherIV
    )
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, UnrecoverableEntryException,
            InvalidAlgorithmParameterException, NoSuchProviderException,
            KeyStoreException, IllegalBlockSizeException, MDecryptorException,
            MKeyWrapperException, IOException, ClassNotFoundException
    {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION_LARGE);
        SecretKey largeKey = getUnwrappedLargeKey( alias, context );

        // TODO give the possibility of custom parameters
        IvParameterSpec specs = new IvParameterSpec( cipherIV );
        cipher.init( Cipher.DECRYPT_MODE, largeKey, specs );

        return cipher;
    }

    /**
     * Loads a {@link SecretKey} used in the encryption process of large
     * chunks of data in SDKs previous to 23.
     *
     * It relies on the utility method {@link MKeyWrapper#loadWrappedLargeKey(Context, Key, String)}
     * to load the key.
     *
     * This method is to be called only by SDKs previous to 23, otherwise
     * it will throw an {@link MDecryptorException}.
     *
     * @param alias unique identifier tight to standard secret key.
     * @param context current Context.
     * @return a {@link SecretKey} to be used in the decryption of large chunks of data.
     *
     * @throws NoSuchPaddingException
     * @throws UnrecoverableEntryException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws MDecryptorException
     * @throws MKeyWrapperException
     *
     * @see MKeyWrapper#loadWrappedLargeKey(Context, Key, String)
     */
    protected SecretKey getUnwrappedLargeKey(
            @NonNull String alias, @NonNull Context context
    )
            throws NoSuchPaddingException, UnrecoverableEntryException,
            NoSuchAlgorithmException, KeyStoreException, InvalidKeyException,
            NoSuchProviderException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, MDecryptorException, MKeyWrapperException,
            IOException, ClassNotFoundException
    {

        Key key;

        if ( Build.VERSION.SDK_INT < 23 ) {
            key = getKeyPair( alias ).getPrivate();
            MKeyWrapper keyWrapper = new MKeyWrapper();
            return keyWrapper.loadWrappedLargeKey( context, key, ALIAS_LARGE );
        }
        throw new MDecryptorException("SDK 23+ doesn't rely on Large Secret Keys");
    }

    // Getters and Setters


    @Override
    public String getAlias() {
        return ALIAS;
    }

    void setTRANSFORMATION(String TRANSFORMATION) {
        this.TRANSFORMATION = TRANSFORMATION;
        this.transformationStandard = false;
    }

    void setTRANSFORMATION_LARGE(String TRANSFORMATION_LARGE) {
        this.TRANSFORMATION_LARGE = TRANSFORMATION_LARGE;
    }

    public boolean isTransformationStandard() {
        return transformationStandard;
    }

    public void setSTANDARD_SPECS(AlgorithmParameterSpec STANDARD_SPECS) {
        this.SPECS = STANDARD_SPECS;
    }

    public void setPROTECTION_PARAMS(
            KeyStore.ProtectionParameter PROTECTION_PARAMS
    ) {
        this.PROTECTION_PARAMS = PROTECTION_PARAMS;
    }


}

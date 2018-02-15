package com.tinmegali.security.mcipher;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.util.Log;

import com.tinmegali.security.mcipher.exceptions.EncryptorException;
import com.tinmegali.security.mcipher.exceptions.KeyWrapperException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

/**
 * Encrypt data using Android KeyStore
 */

@SuppressWarnings("JavaDoc")
public class MEncryptor {

    private final String TAG = MEncryptor.class.getSimpleName();
    private KeyStore keyStore;

    public MEncryptor() throws EncryptorException {
        try {
            initKeyStore();
        } catch (CertificateException | KeyStoreException
                | IOException | NoSuchAlgorithmException e) {
            String errorMsg =
                    String.format("Something went wrong while initiating the KeyStore." +
                            "%n\t%s", e.getMessage());
            Log.e(TAG, errorMsg);
            throw new EncryptorException( errorMsg, e );
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
    private void initKeyStore()
            throws CertificateException, NoSuchAlgorithmException,
            IOException, KeyStoreException
    {
        Log.i(TAG, "initKeyStore()");
        keyStore = KeyStore.getInstance( Constants.ANDROID_KEY_STORE );
        keyStore.load( null );
    }

    /**
     * Encrypt a given String using an appropriate algorithm RSA or AES according
     * to the Android version used.
     *
     * Notice that in SDK versions previous to 23, to encrypt big chunks of data
     * this method won't work. For those situations, use
     * {@link MEncryptor#encryptLargeData(String, String, Context)}.
     *
     * @param alias         unique name used by to the SecretKey/SecretPair and Cipher
     * @param textToEncrypt String to encrypt. For API previous to 23, the text must be smaller
     *                      than 250 symbols.
     * @return  a serialized byte array of a {@link MEncryptedObject},
     * containing the encrypted data and some the IV vector, if needed.
     * @throws EncryptorException   a wrapper {@link Exception}.
     */
    public byte[] encrypt(
            @NonNull final String alias,
            @NonNull final String textToEncrypt,
            @Nullable final Context context )
            throws EncryptorException {
        Log.i(TAG, String.format("encrypt( %s, %s )", alias, textToEncrypt ));
        try
        {
            // get the appropriate cipher for the current SDK
            Cipher cipher = cipherForEncrypt( alias, context );

            // get an encrypted byte[], containing a IV vector if needed.

//            Log.i(TAG, String.format("Encrypted: %n\t%s", encryptedStr ));
            return encryptData( MCipherUtils.decode( textToEncrypt ), cipher );

        }
        catch (UnrecoverableEntryException | NoSuchAlgorithmException
                | NoSuchProviderException | KeyStoreException
                | InvalidKeyException | NoSuchPaddingException
                | InvalidAlgorithmParameterException | IOException
                | BadPaddingException | SignatureException
                | IllegalBlockSizeException e) {

            String errorMsg = String.format(
                    "Something went wrong while trying to encrypt." +
                            "%n\tException: [%s]" +
                            "%n\tCause: %s",
                    e.getClass().getSimpleName(), e.getCause() );
            Log.e(TAG, errorMsg );
            throw new EncryptorException( errorMsg, e );
        }
    }

    /**
     * Uses AES algorithm to encrypt large chunks of data. If the method
     * is called from SDK 23+, it will make a standard encryption operation,
     * calling {@link MEncryptor#encrypt(String, String, Context)}. If the method
     * id called from SDK < 23, it will make the encryption using
     * an AES algorithm, from the Bouncy Castle provider calling
     * {@link MEncryptor#wrapperCipher(String, Context)} to get the cipher and
     * then calling {@link MEncryptor#encryptData(byte[], Cipher)} providing the cipher.
     *
     * @param alias unique identifier to get/generate the standard SecretKey
     * @param dataToEncrypt data to encrypt
     * @param context current Context
     * @return an encrypted byte array of the data
     * @throws EncryptorException for any errors.
     */
    public byte[] encryptLargeData(
            @NonNull final String alias,
            @NonNull final String dataToEncrypt,
            @NonNull final Context context
    ) throws EncryptorException {

        try {
            if ( Build.VERSION.SDK_INT >= 23 ) {
                return encrypt( alias, dataToEncrypt, context);
            } else {
                Cipher cipher = wrapperCipher( alias, context );
                return encryptData(  MCipherUtils.decode(dataToEncrypt) , cipher );
            }
        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException | InvalidKeyException
                | NoSuchProviderException | KeyStoreException
                | IllegalBlockSizeException | UnrecoverableEntryException
                | IOException | SignatureException | BadPaddingException e)
        {
            String errorMsg = String.format(
                    "Something went wrong while trying to encrypt." +
                            "%n\tException: [%s]" +
                            "%n\tCause: %s",
                    e.getClass().getSimpleName(), e.getCause() );
            throw new EncryptorException( errorMsg, e );
        }


    }

    /**
     * Encrypt a given {@link String} using the given {@link Cipher}, returning an
     * serialized byte array of a {@link MEncryptedObject}. The serialization process is
     * done using {@link MEncryptedObject#serializeEncryptedObj(byte[])} for encryption
     * process that using 'RSA' algorithm (API < 23) and
     * {@link MEncryptedObject#serializeEncryptedObj(byte[], byte[])} for encryption with
     * 'AES' algorithm (API23+).
     *
     * @param toEncrypt The data to encrypt. It must use a charset UTF-8.
     * @param cipher    The correct Cipher for the encryption process. The cipher must be
     *                  initialized correctly, taking into consideration the current API
     *                  and chosen operations.
     * @return          A serialized {@link MEncryptedObject}, containing the necessary
     * information for a future description: The IV vector.
     *
     * @throws UnrecoverableEntryException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws InvalidAlgorithmParameterException
     * @throws SignatureException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    private byte[] encryptData(final byte[] toEncrypt, Cipher cipher )
            throws UnrecoverableEntryException, NoSuchAlgorithmException,
            KeyStoreException, NoSuchProviderException, NoSuchPaddingException,
            InvalidKeyException, IOException, InvalidAlgorithmParameterException,
            SignatureException, BadPaddingException, IllegalBlockSizeException
    {
        // Log.i(TAG, String.format("encryptData( %s )", textToEncrypt ));

        // Add the cipher IV at the encrypted data
        byte[] encryptedData = cipher.doFinal( toEncrypt );

        // cipherIV will be null for Android API < 23,
        // unless this operation is related to a big data operation
        byte[] cipherIV = cipher.getIV();

        return MEncryptedObject.serializeEncryptedObj( encryptedData, cipherIV );
    }

    /**
     * Initialize and return a {@link Cipher} appropriate for the current SDK.
     * The Cipher will use different transformations, according to the SDK.
     * For API 23+, the 'AES/GCM/NoPadding' and for APIs between
     * 18 and 22, 'RSA/ECB/PKCS1Padding'.
     *
     * The Cipher also will be initialized with a {@link KeyPair} or {@link SecretKey},
     * according to the current Android SDK: {@link KeyPair} for API 18 < 23 and
     * {@link SecretKey} for API 23+.

     * @param alias     a unique identifies that is or will be tight to a {@link KeyPairGenerator}
     *                  or {@link KeyGenerator}
     * @param context   current Context. It is only used for calls on API previous to 23.
     * @return  A {@link Cipher} appropriate only for encryption operations.
     */
    private Cipher cipherForEncrypt(@NonNull final String alias, @Nullable Context context )
    {
        try {
            final Cipher cipher = Cipher.getInstance( Constants.TRANSFORMATION );

            if ( Build.VERSION.SDK_INT >= 23 )
            {
                // using Symmetric SecretKey to encrypt
                // for API 23+
                cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(alias));
            }
            else
            {
                // using Asymmetric KeyPair's public key to encrypt
                // for API 18+
                assert context != null;
                cipher.init(Cipher.ENCRYPT_MODE,
                        getKeyPair(alias, context).getPublic());
            }
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | NoSuchProviderException | UnrecoverableKeyException
                | InvalidAlgorithmParameterException | KeyStoreException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Tries to recover a {@link SecretKey} from the {@link KeyStore} using
     * the given 'alias'. If a SecretKey is not found, it calls the
     * {@link MEncryptor#generateSecretKey(String)}, that generates and
     * returns the SecretKey.
     *
     * @param alias unique identifier used to store the {@link SecretKey}.
     * @return the {@link SecretKey} associated with the give 'alias'
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    private SecretKey getSecretKey(String alias)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, KeyStoreException,
            UnrecoverableKeyException
    {
        // tries to recover SecretKey from KeyStore
        SecretKey key = (SecretKey) keyStore.getKey(alias, null);

        if (key == null) {
            return generateSecretKey(alias);
        }

        return key;
    }

    /**
     * Generates a {@link SecretKey} for the given 'alias'. The 'alias' is
     * an unique identifier that will be used to store the key in the {@link KeyStore}.
     *
     * The {@link KeyGenerator} will use the 'AES' algorithm with 'AndroidKeyStore' provider.
     *
     * To be used only with Android 23+. For API between 18 an 22, use {@link MEncryptor#generateKeyPair(String, Context)}.
     *
     * @param alias an unique identifier that is(or will be) tight to a {@link KeyGenerator}.
     * @return  A symmetric key. {@link SecretKey}
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    private SecretKey generateSecretKey( String alias )
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, KeyStoreException,
            UnrecoverableKeyException
    {
            // Getting Key Generator with the symmetric algorithm AES
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, Constants.ANDROID_KEY_STORE
            );

            // defining keyGen Parameters
            KeyGenParameterSpec specs =
                    new KeyGenParameterSpec.Builder(alias,
                            KeyProperties.PURPOSE_ENCRYPT
                                    | KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .build();

            keyGenerator.init(specs);

            return keyGenerator.generateKey();
    }

    /**
     * Tries to recover a {@link KeyPair} from the {@link KeyStore} with the
     * given 'alias'. If there isn't such KeyPair, it calls {@link MEncryptor#generateKeyPair(String, Context)},
     * returning the generated KeyPair.
     * @param alias an unique identifies that is or will be tight to the KeyPair
     * @param context the current Context
     * @return a valid {@link KeyPair}
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     */
    private KeyPair getKeyPair(
            @NonNull String alias, @NonNull Context context
    ) throws UnrecoverableKeyException, NoSuchAlgorithmException,
            KeyStoreException, NoSuchProviderException,
            InvalidAlgorithmParameterException
    {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        Certificate certificate = keyStore.getCertificate(alias);
        PublicKey publicKey = null;

        if (certificate != null) {
            publicKey = certificate.getPublicKey();
        }

        if ( privateKey != null && publicKey != null )
        {
            Log.d(TAG, "getKeyPair: recovering from KeyStore");
            return new KeyPair(publicKey, privateKey);
        } else {
            Log.d(TAG, "getKeyPair: generating a new KeyPair");
            return generateKeyPair( alias, context );
        }
    }

    /**
     * Get a {@link KeyPair} from a given 'alias'. The 'alias' is
     * an unique identifier that is(or will be) tight to a {@link KeyPairGenerator}.
     * The {@link KeyPairGenerator} will use the 'RSA' algorithm and the
     * 'AndroidKeyStore' provider.
     *
     * To be used only with Android 18 till 22. For API 23+ use {@link MEncryptor#generateSecretKey(String)}.
     *
     * @param alias     An unique identifier that is(or will be) tight to a {@link KeyPairGenerator}
     * @param context   Current Context
     * @return  A asymmetric key. {@link KeyPair} containing a 'public' and a 'secret' key
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     */
    private KeyPair generateKeyPair( String alias, Context context )
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {

        final KeyPairGenerator keyGenerator =
                KeyPairGenerator.getInstance(
                        "RSA",
                        Constants.ANDROID_KEY_STORE);

        final Calendar startDate = Calendar.getInstance();
        final Calendar endDate = Calendar.getInstance();
        endDate.add(Calendar.YEAR, 20);

        KeyPairGeneratorSpec specs =
                new KeyPairGeneratorSpec.Builder( context )
                        .setAlias( alias )
                        .setSerialNumber(BigInteger.ONE)
                        .setSubject(
                                new X500Principal(
                                        String.format("CN=%s CA Certificate", alias)))
                        .setStartDate(startDate.getTime())
                        .setEndDate(endDate.getTime()).build();

        keyGenerator.initialize( specs );

        return keyGenerator.generateKeyPair();

    }

    /**
     * Generate a {@link Cipher} to be used with the
     * {@link MEncryptor#encryptLargeData(String, String, Context)} when
     * called from SDK < 23.
     * @param alias unique identifier tight to secret key.
     * @param context current Context.
     * @return a {@link Cipher} using {@link Constants#TRANSFORMATION_BC} as its transformation
     * and set to ENCRYPT_MODE.
     *
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws UnrecoverableKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     * @throws IllegalBlockSizeException
     */
    private Cipher wrapperCipher(
            @NonNull final String alias,
            final @NonNull Context context )
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, UnrecoverableKeyException,
            InvalidAlgorithmParameterException, NoSuchProviderException,
            KeyStoreException, IllegalBlockSizeException
    {
        Cipher cipher = Cipher.getInstance( Constants.TRANSFORMATION_BC );
        cipher.init( Cipher.ENCRYPT_MODE, getBCSecretKey( alias, context ) );
        return cipher;
    }

    /**
     * Load or generate a Bouncy Castle secret key. If the key was already wrapped,
     * it is loaded with {@link MKeyWrapper#loadWrappedKey(Context, PrivateKey)},
     * otherwise it is generated and wrapped with {@link MEncryptor#generateBCSecretKey(String, Context)}
     * @param alias unique identifier tight to the secret key.
     * @param context current Context.
     * @return a Bouncy Castle secret key.
     * @throws NoSuchPaddingException
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     */
    private SecretKey getBCSecretKey(
            @NonNull String alias, @NonNull Context context
    )
            throws NoSuchPaddingException, UnrecoverableKeyException,
            NoSuchAlgorithmException, KeyStoreException, InvalidKeyException,
            NoSuchProviderException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException
    {

        MKeyWrapper keyWrapper = new MKeyWrapper();

        KeyPair pair = getKeyPair( alias, context );
        // load Key
        try {
            return keyWrapper
                    .loadWrappedKey( context, pair.getPrivate() );
        } catch (KeyWrapperException e)
        {
            return generateBCSecretKey( alias, context );
        }
    }

    /**
     * Generate a Bouncy Castle AES secret key and wraps it
     * using {@link MKeyWrapper#wrapAndStoreKey(Context, SecretKey, PublicKey)}.
     * @param alias unique identifier tight with standard secret key.
     * @param context current Context
     * @return a Bouncy Castle secret key.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     */
    private SecretKey generateBCSecretKey( final String alias, final Context context)
            throws NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException,
            KeyStoreException, InvalidAlgorithmParameterException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException
    {
        // Get a KeyGenerator using AES algorithm and
        // the BouncyCastle provider. This provider is around
        // in old SDKs, API 19+
        KeyGenerator generator = KeyGenerator
                .getInstance("AES", "BC");

        SecretKey secretKey = generator.generateKey();

        // wrap and store key
        MKeyWrapper keyWrapper = new MKeyWrapper();
        keyWrapper.wrapAndStoreKey( context, secretKey,
                getKeyPair( alias, context ).getPublic() );

        return secretKey;

    }

}

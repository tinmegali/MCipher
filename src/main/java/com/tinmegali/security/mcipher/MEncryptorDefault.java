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

import com.tinmegali.security.mcipher.exceptions.MEncryptorException;
import com.tinmegali.security.mcipher.exceptions.MKeyWrapperException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.x500.X500Principal;

/**
 * Encrypt data using native Android libraries.
 * Compatible with SDK 19+.
 *
 * The encryption process will adapt itself to the current SDK. For
 * SDK previous to 23, it will use by default the "RSA" algorithm to create
 * a asymmetric key with a {@link KeyPair}, composed by a {@link PrivateKey}
 * and a {@link PublicKey}, and a {@link Certificate}. It will also create
 * a 'wrapper' {@link Cipher} when encryptData data bigger than 245 bytes.
 *
 * On SDK 23+, it uses the "AES" algorithm to create a symmetric key {@link SecretKey}
 * by default and doesn't need to rely on 'wrapper' Cipher to encrypt data
 * bigger than 245 bytes.
 *
 * Use the class builder {@link MEncryptorBuilder} to instantiate and
 * configure a {@link MEncryptor} object.
 */
@SuppressWarnings("JavaDoc")
public class MEncryptorDefault implements MEncryptor {

    private final String TAG = MEncryptorDefault.class.getSimpleName();

    // KeyStore
    private KeyStore keyStore;
    private KeyStore.LoadStoreParameter KEYSTORE_PARAMS = null;

    private final String ALIAS;
    private final String ALIAS_LARGE;
    private String TRANSFORMATION = MCipherConstants.TRANSFORMATION;
    private String TRANSFORMATION_LARGE = MCipherConstants.TRANSFORMATION_BC;
    private String KEYSTORE_PROVIDER = MCipherConstants.KEY_STORE_PROVIDER;
    private String PROVIDER_LARGE = MCipherConstants.KEY_STORE_PROVIDER_LARGE;

    private boolean transformationStandard = true;

    private AlgorithmParameterSpec CIPHER_SPECS;
    private KeyStore.ProtectionParameter PROTECTION_PARAMS = null;
    private char[] PASSWORD = null;

    // SecretKey
    private String SECRET_KEY_ALGORITHM = MCipherConstants.ALGORITHM_AES;
    private String[] SECRET_KEY_BLOCK_MODES = { MCipherConstants.BLOCK_MODE_GCM };
    private String[] SECRET_KEY_PADDINGS = { MCipherConstants.PADDING_NO_PADDING };
    private boolean secretKeySpecs = true;
    private KeyGenParameterSpec SECRET_KEY_SPECS = null;
    
    // KeyPair
    private String KEY_PAIR_ALGORITHM = MCipherConstants.ALGORITHM_RSA;
    private boolean certificateStandardDate = true;
    private Date CERTIFICATE_START_DATE = null;
    private Date CERTIFICATE_END_DATE = null;
    private boolean certificateStandardSubject = true;
    private X500Principal CERTIFICATE_SUBJECT = null;
    private boolean keyPairGeneratorSpecsStandard = true;
    private KeyPairGeneratorSpec KEY_PAIR_GENERATOR_SPECS = null;

    // SecretKey Large
    private String SECRET_KEY_LARGE_ALGORITHM = MCipherConstants.ALGORITHM_AES;

    protected MEncryptorDefault(String alias ) {
        ALIAS = alias;
        ALIAS_LARGE = MCipherUtils.getAliasLarge( ALIAS );
    }

    /**
     * Initializes the {@link KeyStore} used in the decryption process. It loads
     * Android's standard KeyStore provider, 'AndroidKeyStore.
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws KeyStoreException
     */
    protected void initKeyStore()
            throws CertificateException, NoSuchAlgorithmException,
            IOException, KeyStoreException
    {
        Log.i(TAG, "initKeyStore()");
        keyStore = KeyStore.getInstance( KEYSTORE_PROVIDER );
        keyStore.load( KEYSTORE_PARAMS );
    }

    /**
     * Decodes and encrypts a given String.
     *
     * @param textToEncrypt a String to be encrypted.
     * @param context the context must only be passed when the method is called from SDK previous to 23.
     * @return a encrypted byte array
     * @throws MEncryptorException
     * @see MCipherUtils#decode(String)
     * @see #encrypt(byte[], Context)
     */
    @Override
    public byte[] encrypt(
            @NonNull final String textToEncrypt,
            @Nullable final Context context )
            throws MEncryptorException {
//        Log.i(TAG, String.format("encrypt( %s )", textToEncrypt));
        byte[] decoded = MCipherUtils.decode(textToEncrypt);

        return encrypt(decoded, context);
    }

    /**
     * Encrypts a given String, retuning an encrypted String encoded
     * with {@link MCipherUtils#encodeEncrypted(byte[])}.
     *
     * @param textToEncrypt a String to be encrypted.
     * @param context the context must only be passed when the method is called from SDK previous to 23.
     * @return a encrypted String encoded with {@link MCipherUtils#encodeEncrypted(byte[])}.
     * @throws MEncryptorException
     * @see MCipherUtils#decode(String)
     * @see MCipherUtils#encodeEncrypted(byte[])
     * @see #encrypt(byte[], Context)
     */
    @Override
    public String encryptString(
            @NonNull String textToEncrypt,
            @Nullable Context context
    ) throws MEncryptorException
    {
//        Log.i(TAG, String.format("encrypt( %s )", textToEncrypt));
        byte[] decoded = MCipherUtils.decode(textToEncrypt);
        byte[] encrypted = encrypt( decoded, context );
        return MCipherUtils.encodeEncrypted( encrypted );
    }

    /**
     * Encrypts a given byte array, returning a encrypted byte array.
     *
     * It calls a different process {@link #encryptLarge(byte[], Cipher, byte[])}
     * for big chunks of data, when the method is called from SDK previous to 23.
     *
     * For smaller chunks of data or any size of data called from SDK 23+, the encryption
     * is done by the {@link #encryptLargeData(byte[], Context)} method.
     *
     * @param dataToEncrypt byte array to be encrypted.
     * @param context the context must only be passed when the method is called from SDK previous to 23.
     * @return a encrypted byte array.
     * @throws MEncryptorException
     * @see #encryptData(byte[], Cipher)
     * @see #encryptLargeData(byte[], Context)
     */
    @Override
    public byte[] encrypt(
            @NonNull final byte[] dataToEncrypt,
            @Nullable final Context context )
            throws MEncryptorException {
        try
        {
            // call 'encryptLargeData' for big block sizes
            // called from older SDKs
            if ( Build.VERSION.SDK_INT < 23 && dataToEncrypt.length >= (256-11) ) {
                if ( context == null )
                {
                    String msg = "Context cannot be null when calling 'encryptData' from" +
                            "older SDKs (SDK < 23).";
                    throw new MEncryptorException( msg );
                }
                return encryptLargeData( dataToEncrypt, context );
            }

            // get the appropriate cipher for the current SDK
            Cipher cipher = cipherForEncrypt(ALIAS, context );

            // get an encrypted byte[], containing a IV vector if needed.
//            Log.i(TAG, String.format("Encrypted: %n\t%s", encryptedStr ));
            return encryptData( dataToEncrypt, cipher );

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
                            "%n\tMessage: %s" +
                            "%n\tCause: %s",
                    e.getClass().getSimpleName(),
                    e.getMessage(),
                    e.getCause() );
            Log.e(TAG, errorMsg );
            throw new MEncryptorException( errorMsg, e );
        }
    }

    /**
     * Uses AES algorithm to encrypt large chunks of data. If the method
     * is called from SDK 23+, it will make a standard encryption operation,
     * calling {@link MEncryptorDefault#encrypt(String, Context)}. If the method
     * id called from SDK < 23, it will make the encryption using
     * an AES algorithm, from the Bouncy Castle provider calling
     * {@link MEncryptorDefault#cipherLargeData(String, Context, byte[])}.
     *
     * @param dataToEncrypt data to encrypt
     * @param context current Context
     * @return an encrypted byte array of the data
     * @throws MEncryptorException for any errors.
     * @see #cipherLargeData(String, Context, byte[])
     * @see #encryptLarge(byte[], Cipher, byte[])
     */
    byte[] encryptLargeData(
            @NonNull final byte[] dataToEncrypt,
            @NonNull final Context context
    ) throws MEncryptorException {

        try {
            if ( Build.VERSION.SDK_INT >= 23 ) {
                return encrypt( dataToEncrypt, context );
            } else {
                byte[] iv = MCipherUtils.generateIV();
                Cipher cipher = cipherLargeData( ALIAS_LARGE, context, iv );
                return encryptLarge(  dataToEncrypt , cipher, iv );
            }
        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException | InvalidKeyException
                | NoSuchProviderException | KeyStoreException
                | IllegalBlockSizeException | UnrecoverableEntryException
                | IOException | SignatureException | ClassNotFoundException
                | BadPaddingException e)
        {
            String errorMsg = String.format(
                    "Something went wrong while trying to encrypt." +
                            "%n\tException: [%s]" +
                            "%n\tCause: %s",
                    e.getClass().getSimpleName(), e );
            throw new MEncryptorException( errorMsg, e );
        }


    }

    /**
     * Encrypt a given byte array using the given {@link Cipher}, returning an
     * serialized byte array of a {@link MEncryptedObject}. The serialization process is
     * done using {@link MEncryptedObject#serializeEncryptedObj(byte[])}.
     *
     * @param toEncrypt The data to encrypt. It must use a charset UTF-8.
     * @param cipher    The correct Cipher for the encryption process. The cipher must be
     *                  initialized correctly, taking into consideration the current API
     *                  and chosen operations.
     * @return          A serialized {@link MEncryptedObject}, containing the necessary
     * information for a future description: The IV vector
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
     * @see MEncryptedObject#serializeEncryptedObj(byte[], byte[])
     */
    protected byte[] encryptData(final byte[] toEncrypt, Cipher cipher )
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

    private byte[] encryptLarge(final byte[] toEncrypt, Cipher cipher, byte[] iv)
            throws UnrecoverableEntryException, NoSuchAlgorithmException,
            KeyStoreException, NoSuchProviderException, NoSuchPaddingException,
            InvalidKeyException, IOException, InvalidAlgorithmParameterException,
            SignatureException, BadPaddingException, IllegalBlockSizeException
    {
        // Add the cipher IV at the encrypted data
        byte[] encryptedData = cipher.doFinal( toEncrypt );

        return MEncryptedObject.serializeLargeEncryptedObj( encryptedData, iv );
    }

    /**
     * Initialize and return a {@link Cipher} appropriate for the current SDK.
     * The Cipher will use different transformations, according to the SDK.
     *
     * By default, for API 23+, the 'AES/GCM/NoPadding' and for APIs between
     * 18 and 22, 'RSA/ECB/PKCS1Padding'.
     *
     * The Cipher also will be initialized with a {@link KeyPair} or {@link SecretKey},
     * according to the current Android SDK: {@link KeyPair} for API 18 < 23 and
     * {@link SecretKey} for API 23+.

     * @param alias     a unique identifies that is or will be tight to a {@link KeyPairGenerator}
     *                  or {@link KeyGenerator}
     * @param context   current Context. It is only used for calls on API previous to 23.
     * @return  A {@link Cipher} appropriate only for encryption operations.
     * @see #getSecretKey(String)
     * @see #getKeyPair(String, Context)
     */
    protected Cipher cipherForEncrypt(
            @NonNull final String alias,
            @Nullable Context context
    ) throws MEncryptorException
    {
        try {
            final Cipher cipher = Cipher.getInstance( TRANSFORMATION );

            if ( Build.VERSION.SDK_INT >= 23 )
            {
                // using Symmetric SecretKey to encrypt
                // for API 23+
                // TODO create the possibility of randomness
                if ( isTransformationStandard() ) {
                    cipher.init( Cipher.ENCRYPT_MODE, getSecretKey(alias));
                } else {
                    cipher.init( Cipher.ENCRYPT_MODE, getSecretKey(alias), CIPHER_SPECS);
                }
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
            throw new MEncryptorException("An error occurred during Cipher initialization.", e);
        }
    }

    /**
     * Tries to recover a {@link SecretKey} from the {@link KeyStore} using
     * the given 'alias'. If a SecretKey is not found, it calls the
     * {@link MEncryptorDefault#generateSecretKey(String)}, that generates and
     * returns the SecretKey.
     *
     * @param alias unique identifier used to store the {@link SecretKey}.
     * @return the {@link SecretKey} associated with the give 'alias'
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     * @see #generateSecretKey(String)
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    protected SecretKey getSecretKey(String alias)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, KeyStoreException,
            UnrecoverableKeyException
    {
        // tries to recover SecretKey from KeyStore
        Key key = keyStore.getKey(alias, PASSWORD);
        if (key == null || !(key instanceof SecretKey) ) {
            return generateSecretKey(alias);
        }

        return (SecretKey) key;
    }

    /**
     * Generates a {@link SecretKey} for the given 'alias'. The 'alias' is
     * an unique identifier that will be used to store the key in the {@link KeyStore}.
     *
     * By default, the {@link KeyGenerator} will use the 'AES' algorithm with 'AndroidKeyStore' provider.
     *
     * To be used only with Android 23+.
     *
     * @param alias an unique identifier that is(or will be) tight to a {@link KeyGenerator}.
     * @return  A symmetric key. {@link SecretKey}
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    protected SecretKey generateSecretKey( String alias )
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, KeyStoreException,
            UnrecoverableKeyException
    {
            // Getting Key Generator with the symmetric algorithm AES
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    SECRET_KEY_ALGORITHM,
                    KEYSTORE_PROVIDER
            );

            // defining keyGen Parameters
            KeyGenParameterSpec specs;
            if ( isSecretKeySpecs() ) {
                specs =
                        new KeyGenParameterSpec.Builder(alias,
                                KeyProperties.PURPOSE_ENCRYPT
                                        | KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(SECRET_KEY_BLOCK_MODES)
                                .setEncryptionPaddings(SECRET_KEY_PADDINGS)
                                .build();
            } else {
                specs = SECRET_KEY_SPECS;
            }

            keyGenerator.init(specs);

            return keyGenerator.generateKey();
    }

    /**
     * Tries to recover a {@link KeyPair} from the {@link KeyStore} with the
     * given 'alias'. If there isn't such KeyPair, it calls {@link MEncryptorDefault#generateKeyPair(String, Context)},
     * returning the generated KeyPair.
     *
     * @param alias an unique identifies that is or will be tight to the KeyPair
     * @param context the current Context
     * @return a valid {@link KeyPair}
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @see #generateKeyPair(String, Context)
     */
    protected KeyPair getKeyPair(
            @NonNull String alias, @NonNull Context context
    ) throws UnrecoverableKeyException, NoSuchAlgorithmException,
            KeyStoreException, NoSuchProviderException,
            InvalidAlgorithmParameterException
    {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, PASSWORD);
        Certificate certificate = keyStore.getCertificate(alias);
        PublicKey publicKey = null;

        if (certificate != null) {
            publicKey = certificate.getPublicKey();
        }

        if ( privateKey != null && publicKey != null )
        {
//            Log.d(TAG, "getKeyPair: recovering from KeyStore");
            return new KeyPair(publicKey, privateKey);
        } else {
//            Log.d(TAG, "getKeyPair: generating a new KeyPair");
            return generateKeyPair( alias, context );
        }
    }

    /**
     * Generates a {@link KeyPair} with the given 'alias'. The 'alias' is
     * an unique identifier that is(or will be) tight to a {@link KeyPairGenerator}.
     *
     * By default, the {@link KeyPairGenerator} will use the 'RSA' algorithm and the
     * 'AndroidKeyStore' provider. Also, the {@link javax.security.cert.Certificate} used
     * is a mocked one, valid until {@link #CERTIFICATE_END_DATE}.
     *
     * To be used only with Android 18 till 22.
     *
     * @param alias     An unique identifier that is(or will be) tight to a {@link KeyPairGenerator}
     * @param context   Current Context
     * @return  A asymmetric key. {@link KeyPair} containing a 'public' and a 'secret' key
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     */
    protected KeyPair generateKeyPair( String alias, Context context )
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {

        final KeyPairGenerator keyGenerator =
                KeyPairGenerator.getInstance(
                        KEY_PAIR_ALGORITHM,
                        KEYSTORE_PROVIDER);

        Date startDate;
        Date endDate;
        // check if it is using standard certificate dates
        if ( isCertificateStandardDate() ) {
            final Calendar startCal = Calendar.getInstance();
            final Calendar endCal = Calendar.getInstance();
            endCal.add(Calendar.YEAR, 20);

            startDate = startCal.getTime();
            endDate = endCal.getTime();
        } else {
            startDate = CERTIFICATE_START_DATE;
            endDate = CERTIFICATE_END_DATE;
        }
        // check if it is using standard certificate subject
        X500Principal subject;
        if ( isCertificateStandardSubject() ) {
            subject = new X500Principal(
                    String.format("CN=%s CA Certificate", alias));
        }
        else {
            subject = CERTIFICATE_SUBJECT;
        }

        // check if it is using standard KeyPair generator specs
        KeyPairGeneratorSpec specs;
        if ( isKeyPairGeneratorSpecsStandard() ) {
            specs = new KeyPairGeneratorSpec.Builder( context )
                            .setAlias( alias )
                            .setSerialNumber(BigInteger.ONE)
                            .setSubject( subject )
                            .setStartDate( startDate )
                            .setEndDate( endDate )
                            .build();
        } else {
            specs = KEY_PAIR_GENERATOR_SPECS;
        }

        // TODO give the option to use SecureRandom
        keyGenerator.initialize( specs );

        return keyGenerator.generateKeyPair();

    }

    /**
     * Generate a {@link Cipher} to be used with the in the encryption of
     * large chunks of data, when called from SDK < 23.
     *
     * By default it uses the 'BouncyCastle' provider to obtain a {@link SecretKey}
     * , using the 'AES/GCM/NoPadding' transformation, to obtain a {@link Cipher}
     * responsible to encrypt the large data.
     *
     * The key is generated and the key itself is encrypted using the standard KeyPair
     * and saved in the SharedPreferences for a later use.
     *
     * @param alias unique identifier tight to secret key.
     * @param context current Context.
     * @return a {@link Cipher} using {@link MCipherConstants#TRANSFORMATION_BC} as its transformation
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
     *
     * @see #getBCSecretKey(String, Context)
     */
    protected Cipher cipherLargeData(
            @NonNull final String alias,
            final @NonNull Context context,
            final byte[] iv
    )
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, UnrecoverableKeyException,
            InvalidAlgorithmParameterException, NoSuchProviderException,
            KeyStoreException, IllegalBlockSizeException, IOException,
            ClassNotFoundException
    {
        Cipher cipher = Cipher.getInstance(
                TRANSFORMATION_LARGE, PROVIDER_LARGE );
        // getting Bouncy Castle Secret Key
        SecretKey bcKey = getBCSecretKey( alias, context );

        IvParameterSpec spec = new IvParameterSpec( iv );
        cipher.init( Cipher.ENCRYPT_MODE, bcKey, spec  );

        return cipher;
    }

    /**
     * Load or generate a secret key responsible for the encryption process
     * of lange chunks of data in older SDKs.
     *
     * By default the key is obtained using the 'BouncyCastle' provider and
     * the 'AES/GCM/NoPadding' transformation. Once the key is generated, it is
     * encrypted and saved in the SharedPreferences for a later use.
     *
     * If the key was already generated with the method {@link #generateSecretKeyForLargeOps(Context)},
     * it is loaded from the SharedPreferences by the utility method {@link MKeyWrapper#loadWrappedLargeKey(Context, Key, String)}.
     * and decrypted.
     *
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
     *
     * @see #getKeyPair(String, Context)
     * @see #generateSecretKeyForLargeOps(Context)
     * @see MKeyWrapper#loadWrappedLargeKey(Context, Key, String)
     * @see #wrapAndStoreLargeKey(Context, SecretKey)
     */
    protected SecretKey getBCSecretKey(
            @NonNull final String alias,
            @NonNull final Context context
    )
            throws NoSuchPaddingException, UnrecoverableKeyException,
            NoSuchAlgorithmException, KeyStoreException, InvalidKeyException,
            NoSuchProviderException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, IOException, ClassNotFoundException
    {

        MKeyWrapper keyWrapper = new MKeyWrapper();

        try {
            if (Build.VERSION.SDK_INT < 23) {
                KeyPair pair = getKeyPair(alias, context);

                // load Key
                return keyWrapper
                        .loadWrappedLargeKey(context, pair.getPrivate(), ALIAS_LARGE);
            }
            else
            {
                // SDK 23+
                SecretKey key = getSecretKey(alias);
                return keyWrapper.loadWrappedLargeKey(context, key, ALIAS_LARGE);

            }
        } catch (MKeyWrapperException e) {
            SecretKey bcKey = generateSecretKeyForLargeOps(context);
            wrapAndStoreLargeKey(context, bcKey);
            return bcKey;
        }
    }

    /**
     * Generate a {@link SecretKey} to encrypt large chunks of data
     * in SDKs previous to 23.
     * By default, it uses the 'Bouncy Castle' and the 'AES' algorithm.
     *
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
    protected SecretKey generateSecretKeyForLargeOps(
            final Context context
    )
            throws NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException,
            KeyStoreException, InvalidAlgorithmParameterException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException
    {
        // Get a KeyGenerator using AES algorithm and
        // the BouncyCastle provider. This provider is around
        // in old SDKs, API 19+
        KeyGenerator generator = KeyGenerator.getInstance(
                SECRET_KEY_LARGE_ALGORITHM,
                PROVIDER_LARGE
        );
        generator.init(128, new SecureRandom() );

        return generator.generateKey();

    }

    protected void wrapAndStoreLargeKey(
            Context context,
            SecretKey bcKey
    ) throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException,
            UnrecoverableKeyException, KeyStoreException,
            NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException
    {
        // wrap and store key
        MKeyWrapper keyWrapper = new MKeyWrapper();
        Key wrapperKey = getEncryptionWrapperKey( context );
        keyWrapper.wrapAndStoreKey( context, bcKey, wrapperKey, ALIAS_LARGE );
    }

    protected Key getEncryptionWrapperKey( Context context )
            throws UnrecoverableKeyException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException
    {
        if (Build.VERSION.SDK_INT < 23 ) {
            KeyPair pair = getKeyPair( ALIAS_LARGE, context );
            return pair.getPublic();
        } else {
            return getSecretKey(ALIAS);
        }
    }

    // getters and setters


    void setKEYSTORE_PARAMS(KeyStore.LoadStoreParameter KEYSTORE_PARAMS) {
        this.KEYSTORE_PARAMS = KEYSTORE_PARAMS;
    }

    void setKEYSTORE_PROVIDER(String KEYSTORE_PROVIDER) {
        this.KEYSTORE_PROVIDER = KEYSTORE_PROVIDER;
    }

    @Override
    public String getAlias() {
        return ALIAS;
    }

    public String getALIAS_LARGE() {
        return ALIAS_LARGE;
    }

    void setTRANSFORMATION(String TRANSFORMATION) {
        this.TRANSFORMATION = TRANSFORMATION;
        this.transformationStandard = false;
    }

    private void setTRANSFORMATION_LARGE(String TRANSFORMATION_LARGE) {
        this.TRANSFORMATION_LARGE = TRANSFORMATION_LARGE;
    }

    private boolean isTransformationStandard() {
        return transformationStandard;
    }

    void setCIPHER_SPECS(AlgorithmParameterSpec CIPHER_SPECS) {
        this.CIPHER_SPECS = CIPHER_SPECS;
    }

    void setPROTECTION_PARAMS(
            KeyStore.ProtectionParameter PROTECTION_PARAMS
    ) {
        this.PROTECTION_PARAMS = PROTECTION_PARAMS;
    }

    void setPASSWORD(char[] PASSWORD) {
        this.PASSWORD = PASSWORD;
    }

    void setSECRET_KEY_ALGORITHM(String SECRET_KEY_ALGORITHM) {
        this.SECRET_KEY_ALGORITHM = SECRET_KEY_ALGORITHM;
    }

    void setSECRET_KEY_BLOCK_MODES(String... SECRET_KEY_BLOCK_MODES) {
        this.SECRET_KEY_BLOCK_MODES = SECRET_KEY_BLOCK_MODES;
    }

    void setSECRET_KEY_PADDINGS(String... SECRET_KEY_PADDINGS) {
        this.SECRET_KEY_PADDINGS = SECRET_KEY_PADDINGS;
    }

    private boolean isSecretKeySpecs() {
        return secretKeySpecs;
    }

    void setSECRET_KEY_SPECS(KeyGenParameterSpec SECRET_KEY_SPECS) {
        this.SECRET_KEY_SPECS = SECRET_KEY_SPECS;
        this.secretKeySpecs = false;
    }

    private boolean isCertificateStandardDate() {
        return certificateStandardDate;
    }

    void setCERTIFICATE_DATE(Date CERTIFICATE_START_DATE, Date CERTIFICATE_END_DATE) {
        this.CERTIFICATE_START_DATE = CERTIFICATE_START_DATE;
        this.CERTIFICATE_END_DATE = CERTIFICATE_END_DATE;
        this.certificateStandardDate = false;
    }

    private boolean isCertificateStandardSubject() {
        return certificateStandardSubject;
    }

    void setCERTIFICATE_SUBJECT(X500Principal CERTIFICATE_SUBJECT) {
        this.CERTIFICATE_SUBJECT = CERTIFICATE_SUBJECT;
        this.certificateStandardSubject = false;
    }

    private boolean isKeyPairGeneratorSpecsStandard() {
        return keyPairGeneratorSpecsStandard;
    }

    void setKEY_PAIR_GENERATOR_SPECS(KeyPairGeneratorSpec KEY_PAIR_GENERATOR_SPECS) {
        this.KEY_PAIR_GENERATOR_SPECS = KEY_PAIR_GENERATOR_SPECS;
        this.keyPairGeneratorSpecsStandard = false;
    }

}

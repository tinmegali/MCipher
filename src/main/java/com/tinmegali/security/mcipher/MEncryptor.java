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
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.x500.X500Principal;

/**
 * Encrypt data using Android KeyStore
 */

@SuppressWarnings("JavaDoc")
public class MEncryptor {

    private final String TAG = MEncryptor.class.getSimpleName();
    private KeyStore keyStore;

    private final String ALIAS;
    private final String ALIAS_LARGE;
    private String TRANSFORMATION = Constants.TRANSFORMATION;
    private String TRANSFORMATION_LARGE = Constants.TRANSFORMATION_BC;
    private String PROVIDER = Constants.PROVIDER_STANDARD;
    private String PROVIDER_LARGE = Constants.PROVIDER_LARGE;

    private boolean transformationStandard = true;

    private AlgorithmParameterSpec CIPHER_SPECS;
    private KeyStore.ProtectionParameter PROTECTION_PARAMS = null;
    private char[] PASSWORD = null;
    // SecretKey
    private String SECRET_KEY_ALGORITHM = "AES";
    private String[] SECRET_KEY_BLOCK_MODES = { "GCM" };
    private String[] SECRET_KEY_PADDINGS = { "NoPadding" };
    private boolean secretKeySpecs = true;
    private KeyGenParameterSpec SECRET_KEY_SPECS = null;
    // KeyPair
    private String KEY_PAIR_ALGORITHM = "RSA";
    private boolean certificateStandardDate = true;
    private Date CERTIFICATE_START_DATE = null;
    private Date CERTIFICATE_END_DATE = null;
    private boolean certificateStandardSubject = true;
    private X500Principal CERTIFICATE_SUBJECT = null;
    private boolean keyPairGeneratorSpecsStandard = true;
    private KeyPairGeneratorSpec KEY_PAIR_GENERATOR_SPECS = null;

    protected MEncryptor( String alias ) throws EncryptorException {
        ALIAS = alias;
        ALIAS_LARGE = ALIAS + "_large";
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
    protected void initKeyStore()
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
     * {@link MEncryptor#encryptLargeData(String, Context)}.
     *
     * @param textToEncrypt String to encrypt. For API previous to 23, the text must be smaller
     *                      than 250 symbols.
     * @return  a serialized byte array of a {@link MEncryptedObject},
     * containing the encrypted data and some the IV vector, if needed.
     * @throws EncryptorException   a wrapper {@link Exception}.
     */
    public byte[] encrypt(
            @NonNull final String textToEncrypt,
            @Nullable final Context context )
            throws EncryptorException {
        Log.i(TAG, String.format("encrypt( %s )", textToEncrypt));
        byte[] decoded = MCipherUtils.decode(textToEncrypt);

        return encrypt(decoded, context);
    }

    public byte[] encrypt(
            @NonNull final byte[] dataToEncrypt,
            @Nullable final Context context )
            throws EncryptorException {
        try
        {
            // call 'encryptLargeData' for big block sizes
            // called from older SDKs
            if ( Build.VERSION.SDK_INT < 23 && dataToEncrypt.length >= (256-11) ) {
                String warnMsg = String.format(
                        "Block size [%s] to large for standard 'RSA' encryption," +
                                "using 'AES'. Try to call 'encryptLargeData()' the next time",
                        dataToEncrypt.length
                );
                Log.w( TAG, warnMsg );
                if ( context == null )
                {
                    String msg = "Context cannot be null when calling 'encrypting' from" +
                            "older SDKs (SDK < 23).";
                    throw new EncryptorException( msg );
                }
                return encryptLargeData( dataToEncrypt, context );
            }

            // get the appropriate cipher for the current SDK
            Cipher cipher = cipherForEncrypt(ALIAS, context );

            // get an encrypted byte[], containing a IV vector if needed.

//            Log.i(TAG, String.format("Encrypted: %n\t%s", encryptedStr ));

            return encrypting( dataToEncrypt, cipher );

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
            throw new EncryptorException( errorMsg, e );
        }
    }

    /**
     * Uses AES algorithm to encrypt large chunks of data. If the method
     * is called from SDK 23+, it will make a standard encryption operation,
     * calling {@link MEncryptor#encrypt(String, Context)}. If the method
     * id called from SDK < 23, it will make the encryption using
     * an AES algorithm, from the Bouncy Castle provider calling
     * {@link MEncryptor#cipherLargeData(String, Context, byte[])}  to get the cipher and
     * then calling {@link MEncryptor#encrypting(byte[], Cipher)} providing the cipher.
     *
     * @param dataToEncrypt data to encrypt
     * @param context current Context
     * @return an encrypted byte array of the data
     * @throws EncryptorException for any errors.
     */
    public byte[] encryptLargeData(
            @NonNull final String dataToEncrypt,
            @NonNull final Context context
    ) throws EncryptorException {

        try {
            if ( Build.VERSION.SDK_INT >= 23 ) {
                return encrypt( dataToEncrypt, context );
            } else {
                byte[] iv = MCipherUtils.generateIV();
                Cipher cipher = cipherLargeData( ALIAS_LARGE, context, iv );
                return encryptingLarge(  MCipherUtils.decode( dataToEncrypt ) , cipher, iv );
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
            throw new EncryptorException( errorMsg, e );
        }


    }

    public byte[] encryptLargeData(
            @NonNull final byte[] dataToEncrypt,
            @NonNull final Context context
    ) throws EncryptorException {

        try {
            if ( Build.VERSION.SDK_INT >= 23 ) {
                return encrypt( dataToEncrypt, context );
            } else {
                byte[] iv = MCipherUtils.generateIV();
                Cipher cipher = cipherLargeData( ALIAS_LARGE, context, iv );
                return encryptingLarge(  dataToEncrypt , cipher, iv );
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
    protected byte[] encrypting(final byte[] toEncrypt, Cipher cipher )
            throws UnrecoverableEntryException, NoSuchAlgorithmException,
            KeyStoreException, NoSuchProviderException, NoSuchPaddingException,
            InvalidKeyException, IOException, InvalidAlgorithmParameterException,
            SignatureException, BadPaddingException, IllegalBlockSizeException
    {
        // Log.i(TAG, String.format("encrypting( %s )", textToEncrypt ));

        // Add the cipher IV at the encrypted data
        byte[] encryptedData = cipher.doFinal( toEncrypt );

        // cipherIV will be null for Android API < 23,
        // unless this operation is related to a big data operation
        byte[] cipherIV = cipher.getIV();

        return MEncryptedObject.serializeEncryptedObj( encryptedData, cipherIV );
    }

    protected byte[] encryptingLarge(final byte[] toEncrypt, Cipher cipher, byte[] iv)
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
    protected Cipher cipherForEncrypt(
            @NonNull final String alias,
            @Nullable Context context
    ) throws EncryptorException
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
            throw new EncryptorException("An error occurred during Cipher initialization.", e);
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
    protected SecretKey generateSecretKey( String alias )
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, KeyStoreException,
            UnrecoverableKeyException
    {
            // Getting Key Generator with the symmetric algorithm AES
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    SECRET_KEY_ALGORITHM,
                    PROVIDER
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
    protected KeyPair generateKeyPair( String alias, Context context )
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {

        final KeyPairGenerator keyGenerator =
                KeyPairGenerator.getInstance(
                        KEY_PAIR_ALGORITHM,
                        PROVIDER);

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
     * Generate a {@link Cipher} to be used with the
     * {@link MEncryptor#encryptLargeData(String, Context)} when
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
     * Load or generate a Bouncy Castle secret key. If the key was already wrapped,
     * it is loaded with {@link MKeyWrapper#loadWrappedBCKey(Context, Key)},
     * otherwise it is generated and wrapped with
     * {@link MEncryptor#generateBCSecretKey(Context)}
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
                        .loadWrappedBCKey(context, pair.getPrivate());
            }
            else
            {
                // SDK 23+
                SecretKey key = getSecretKey(alias);
                return keyWrapper.loadWrappedBCKey(context, key);

            }
        } catch (KeyWrapperException e) {
            SecretKey bcKey = generateBCSecretKey(context);
            wrapAndStoreBCKey(context, bcKey);
            return bcKey;
        }
    }

    /**
     * Generate a Bouncy Castle AES secret key and wraps it
     * using {@link MKeyWrapper#wrapAndStoreKey(Context, SecretKey, Key)}.
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
    protected SecretKey generateBCSecretKey(
            final Context context
    )
            throws NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException,
            KeyStoreException, InvalidAlgorithmParameterException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException
    {
        // Get a KeyGenerator using AES algorithm and
        // the BouncyCastle provider. This provider is around
        // in old SDKs, API 19+
        KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
        generator.init(128, new SecureRandom() );

        return generator.generateKey();

    }

    protected void wrapAndStoreBCKey(
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
        keyWrapper.wrapAndStoreKey( context, bcKey, wrapperKey );
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


    public String getALIAS() {
        return ALIAS;
    }

    public String getALIAS_LARGE() {
        return ALIAS_LARGE;
    }

    private void setTRANSFORMATION(String TRANSFORMATION ) {
        this.TRANSFORMATION = TRANSFORMATION;
        this.transformationStandard = false;
    }

    private void setTRANSFORMATION_LARGE(String TRANSFORMATION_LARGE) {
        this.TRANSFORMATION_LARGE = TRANSFORMATION_LARGE;
    }

    private boolean isTransformationStandard() {
        return transformationStandard;
    }

    private void setCIPHER_SPECS(AlgorithmParameterSpec CIPHER_SPECS) {
        this.CIPHER_SPECS = CIPHER_SPECS;
    }

    private void setPROTECTION_PARAMS(
            KeyStore.ProtectionParameter PROTECTION_PARAMS
    ) {
        this.PROTECTION_PARAMS = PROTECTION_PARAMS;
    }

    private void setPASSWORD(char[] PASSWORD) {
        this.PASSWORD = PASSWORD;
    }

    private void setSECRET_KEY_ALGORITHM(String SECRET_KEY_ALGORITHM) {
        this.SECRET_KEY_ALGORITHM = SECRET_KEY_ALGORITHM;
    }

    private void setSECRET_KEY_BLOCK_MODES(String... SECRET_KEY_BLOCK_MODES) {
        this.SECRET_KEY_BLOCK_MODES = SECRET_KEY_BLOCK_MODES;
    }

    private void setSECRET_KEY_PADDINGS(String... SECRET_KEY_PADDINGS) {
        this.SECRET_KEY_PADDINGS = SECRET_KEY_PADDINGS;
    }

    private boolean isSecretKeySpecs() {
        return secretKeySpecs;
    }

    private void setSECRET_KEY_SPECS(KeyGenParameterSpec SECRET_KEY_SPECS) {
        this.SECRET_KEY_SPECS = SECRET_KEY_SPECS;
        this.secretKeySpecs = false;
    }

    private boolean isCertificateStandardDate() {
        return certificateStandardDate;
    }

    private void setCERTIFICATE_DATE(Date CERTIFICATE_START_DATE, Date CERTIFICATE_END_DATE) {
        this.CERTIFICATE_START_DATE = CERTIFICATE_START_DATE;
        this.CERTIFICATE_END_DATE = CERTIFICATE_END_DATE;
        this.certificateStandardDate = false;
    }

    private boolean isCertificateStandardSubject() {
        return certificateStandardSubject;
    }

    private void setCERTIFICATE_SUBJECT(X500Principal CERTIFICATE_SUBJECT) {
        this.CERTIFICATE_SUBJECT = CERTIFICATE_SUBJECT;
        this.certificateStandardSubject = false;
    }

    private boolean isKeyPairGeneratorSpecsStandard() {
        return keyPairGeneratorSpecsStandard;
    }

    private void setKEY_PAIR_GENERATOR_SPECS(KeyPairGeneratorSpec KEY_PAIR_GENERATOR_SPECS) {
        this.KEY_PAIR_GENERATOR_SPECS = KEY_PAIR_GENERATOR_SPECS;
        this.keyPairGeneratorSpecsStandard = false;
    }

    // builder
    public static class Builder {

        private MEncryptor encryptor;

        public Builder( final String defaultAlias ) throws EncryptorException {
            encryptor = new MEncryptor( defaultAlias );
        }

        public MEncryptor build() {
            return encryptor;
        }

        public MEncryptor.Builder transformation(
                String transformation,
                AlgorithmParameterSpec spec )
        {
            encryptor.setTRANSFORMATION( transformation );
            encryptor.setCIPHER_SPECS( spec );
            return this;
        }

        public MEncryptor.Builder protectionParams(
                KeyStore.ProtectionParameter protectionParameter
        ) {
            encryptor.setPROTECTION_PARAMS( protectionParameter );
            return this;
        }

        public Builder password( char[] password ) {
            encryptor.setPASSWORD( password );
            return this;
        }

        public Builder secretKeyAlgorithm( String algorithm ) {
            encryptor.setSECRET_KEY_ALGORITHM( algorithm );
            return this;
        }

        public Builder secretKeyBlockModes( String... modes ) {
            encryptor.setSECRET_KEY_BLOCK_MODES( modes );
            return this;
        }

        public Builder secretKeyPaddings( String... paddings ) {
            encryptor.setSECRET_KEY_PADDINGS( paddings );
            return this;
        }

        public Builder secretKeySpecs( KeyGenParameterSpec specs ) {
            encryptor.setSECRET_KEY_SPECS( specs );
            return this;
        }

        public Builder certificateDate( Date startDate, Date endDate ) {
            encryptor.setCERTIFICATE_DATE( startDate, endDate );
            return this;
        }

        public Builder certificateSubject( X500Principal subject ) {
            encryptor.setCERTIFICATE_SUBJECT( subject );
            return this;
        }

        public Builder keyPairGeneratorSpecs( KeyPairGeneratorSpec spec ) {
            encryptor.setKEY_PAIR_GENERATOR_SPECS( spec );
            return this;
        }

    }

}

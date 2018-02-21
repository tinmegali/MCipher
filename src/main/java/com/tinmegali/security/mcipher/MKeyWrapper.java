package com.tinmegali.security.mcipher;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.support.annotation.NonNull;
import android.util.Base64;

import com.tinmegali.security.mcipher.exceptions.KeyWrapperException;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Utility class to handle to handle the encryption/decryption and the storage
 * of keys used in encryption and decryption operation for large chunks of data
 * in SDK previous to 23.
 *
 */

@SuppressWarnings("JavaDoc")
public class MKeyWrapper {

    /**
     * Wraps and stores a {@link SecretKey}. The 'keyToWrap' is
     * encrypted using the 'keyToWrapWith' and than saved in the
     * Shared Preferences.
     * @param context current Context.
     * @param keyToWrap {@link SecretKey} to wrap.
     * @param keyToWrapWith {@link PublicKey} to
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @see MKeyWrapper#wrapKey(Key, Key)
     * @see MKeyWrapper#storeKey(Context, String)
     */
    protected void wrapAndStoreKey(
            @NonNull Context context,
            @NonNull SecretKey keyToWrap,
            @NonNull Key keyToWrapWith
    ) throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException,
            UnrecoverableKeyException, KeyStoreException,
            NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException
    {
        byte[] wrapped = wrapKey( keyToWrap, keyToWrapWith );
        String wrappedKey = Base64.encodeToString( wrapped, Base64.DEFAULT );
        storeKey(context, wrappedKey);
    }

    /**
     * Store a encrypted secret key ('wrappedKey') in the Shared Preferences.
     * @param context current Context.
     * @param wrappedKey encrypted Bouncy Castle secret key.
     * @see MKeyWrapper#wrapAndStoreKey(Context, SecretKey, Key)
     * @see Constants#PREFS_NAME
     * @see Constants#WRAPPED_KEY
     */
    protected void storeKey(Context context, String wrappedKey) {
        SharedPreferences pref = context
                .getSharedPreferences( Constants.PREFS_NAME,
                        Context.MODE_PRIVATE );

        SharedPreferences.Editor editor = pref.edit();
        editor.putString( Constants.WRAPPED_KEY, wrappedKey );
        editor.apply();
    }

    /**
     * Encrypts a {@link Key} using a {@link Cipher} set with
     * {@link Cipher#WRAP_MODE} and using as {@link Key} the 'keyToWrapWith'.
     *
     * @param keyToWrap key to encrypt ('wrap')
     * @param keyToWrapWith key to be used by tge Cipher.
     * @return a encoded String of the encrypted key.
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @see MKeyWrapper#wrapAndStoreKey(Context, SecretKey, Key)
     */
    protected byte[] wrapKey(
            @NonNull final Key keyToWrap,
            @NonNull final Key keyToWrapWith
    )
            throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException,IOException
    {

        Cipher cipher = Cipher.getInstance( Constants.TRANSFORMATION );
        cipher.init( Cipher.WRAP_MODE, keyToWrapWith );

        return MEncryptedObject.serializeEncryptedObj( cipher.wrap( keyToWrap ), cipher.getIV() );
    }

    /**
     * Loads from Shared Preferences
     * a {@link SecretKey} that was already 'wrapped' and 'stored'
     * with method {@link MKeyWrapper#wrapAndStoreKey(Context, SecretKey, Key)}.
     * If the key isn't found, throws a {@link KeyWrapperException}.
     * @param context current Context.
     * @param wrapperKey the {@link Key} to be used in the decryption.
     * @return the saved key.
     * @throws UnrecoverableKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws KeyWrapperException
     * @see MKeyWrapper#unWrapKey(byte[], Key)
     */
    protected SecretKey loadWrappedBCKey(
            Context context, Key wrapperKey
    ) throws UnrecoverableKeyException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            KeyStoreException, NoSuchProviderException, InvalidKeyException,
            NoSuchPaddingException, KeyWrapperException, IOException,
            ClassNotFoundException
    {
        SharedPreferences pref = context
                .getSharedPreferences( Constants.PREFS_NAME,
                        Context.MODE_PRIVATE );
        String wrappedKey = pref.getString( Constants.WRAPPED_KEY, null );

        if ( wrappedKey == null ) {
            String msg = "There isn't any Wrapped Keys to load.";
            throw new KeyWrapperException( msg );
        }

        byte[] wrappedData = Base64.decode( wrappedKey, Base64.DEFAULT );
        return (SecretKey) unWrapKey( wrappedData, wrapperKey );


    }

    /**
     * Unwraps (decrypts) an encrypted {@link Key}.
     * @param wrappedObj the encrypted key.
     * @param keyToUnWrap the {@link Key} responsible to decrypt the key.
     * @return and decrypted {@link Key}.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @see MCipherUtils#decode(String)
     */
    protected Key unWrapKey(
            @NonNull byte[] wrappedObj,
            @NonNull Key keyToUnWrap
    )
            throws NoSuchPaddingException, IOException, ClassNotFoundException,
            NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException
    {

        MEncryptedObject obj = MEncryptedObject.getEncryptedObject( wrappedObj );

        Cipher cipher = Cipher.getInstance( Constants.TRANSFORMATION );
        String algorithm;
        if (Build.VERSION.SDK_INT <23 ) {
            algorithm = "RSA";
//            algorithm = Constants.TRANSFORMATION;
            cipher.init( Cipher.UNWRAP_MODE, keyToUnWrap );
            // FIXME it doesn't work with api < 23
            return cipher.unwrap( obj.getData(), algorithm, Cipher.SECRET_KEY );
        }
        else {
            algorithm = "AES";
            final GCMParameterSpec specs = new GCMParameterSpec( 128, obj.getCypherIV() );
            cipher.init( Cipher.UNWRAP_MODE, keyToUnWrap, specs );
            return cipher.unwrap( obj.getData(), algorithm, Cipher.SECRET_KEY );
        }


    }

}

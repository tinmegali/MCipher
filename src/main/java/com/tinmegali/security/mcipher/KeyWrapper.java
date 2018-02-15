package com.tinmegali.security.mcipher;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import com.tinmegali.security.mcipher.exceptions.KeyWrapperException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * Utility class to handle to handle the encryption/decryption and the storage
 * of keys used in encryption and decryption operation for large chunks of data
 * in SDK previous to 23.
 *
 */

@SuppressWarnings("JavaDoc")
class KeyWrapper {

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
     * @see KeyWrapper#wrapKey(Key, Key)
     * @see KeyWrapper#storeKey(Context, String)
     */
    void wrapAndStoreKey(
            Context context, SecretKey keyToWrap, PublicKey keyToWrapWith
    ) throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException,
            UnrecoverableKeyException, KeyStoreException,
            NoSuchProviderException, InvalidAlgorithmParameterException
    {
        String wrappedKey = wrapKey( keyToWrap, keyToWrapWith );

        storeKey(context, wrappedKey);
    }

    /**
     * Store a encrypted secret key ('wrappedKey') in the Shared Preferences.
     * @param context current Context.
     * @param wrappedKey encrypted Bouncy Castle secret key.
     * @see KeyWrapper#wrapAndStoreKey(Context, SecretKey, PublicKey)
     * @see Constants#PREFS_NAME
     * @see Constants#WRAPPED_KEY
     */
    private void storeKey(Context context, String wrappedKey) {
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
     * @see KeyWrapper#wrapAndStoreKey(Context, SecretKey, PublicKey)
     */
    private String wrapKey(Key keyToWrap, Key keyToWrapWith )
            throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException
    {

        Cipher cipher = Cipher.getInstance( Constants.TRANSFORMATION );
        cipher.init( Cipher.WRAP_MODE, keyToWrapWith );

        byte[] encryptedKey = cipher.wrap( keyToWrap );

        return Base64.encodeToString( encryptedKey, Base64.DEFAULT );
    }

    /**
     * Loads from Shared Preferences
     * a {@link SecretKey} that was already 'wrapped' and 'stored'
     * with method {@link KeyWrapper#wrapAndStoreKey(Context, SecretKey, PublicKey)}.
     * If the key isn't found, throws a {@link KeyWrapperException}.
     * @param context current Context.
     * @param privateKey the {@link PrivateKey} to be used in the decryption.
     * @return the saved key.
     * @throws UnrecoverableKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws KeyWrapperException
     * @see KeyWrapper#unWrapKey(String, Key)
     */
    SecretKey loadWrappedKey(
            Context context, PrivateKey privateKey
    ) throws UnrecoverableKeyException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            KeyStoreException, NoSuchProviderException, InvalidKeyException,
            NoSuchPaddingException, KeyWrapperException {
        SharedPreferences pref = context
                .getSharedPreferences( Constants.PREFS_NAME,
                        Context.MODE_PRIVATE );
        String wrappedKey = pref.getString( Constants.WRAPPED_KEY, null );

        if ( wrappedKey == null ) {
            String msg = "There isn't any Wrapped Keys to load.";
            throw new KeyWrapperException( msg );
        }

        return (SecretKey) unWrapKey( wrappedKey, privateKey );


    }

    /**
     * Unwraps (decrypts) an encrypted {@link Key}.
     * @param wrappedKey the encrypted key.
     * @param keyToUnWrap the {@link Key} responsible to decrypt the key.
     * @return and decrypted {@link Key}.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @see CipherUtils#decode(String)
     * @see KeyWrapper#loadWrappedKey(Context, PrivateKey)
     */
    private Key unWrapKey(String wrappedKey, Key keyToUnWrap )
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException
    {
        byte[] encryptedData = CipherUtils.decode( wrappedKey );

        Cipher cipher = Cipher.getInstance( Constants.TRANSFORMATION );
        cipher.init( Cipher.UNWRAP_MODE, keyToUnWrap );
        return cipher.unwrap( encryptedData, "RSA", Cipher.SECRET_KEY );
    }

}

package com.tinmegali.security.mcipher.testClasses;

import android.content.Context;
import android.support.annotation.NonNull;

import com.tinmegali.security.mcipher.MKeyWrapper;
import com.tinmegali.security.mcipher.exceptions.KeyWrapperException;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * com.tinmegali.security.mcipher.testClasses | MCipher
 * __________________________________
 * Created by tinmegali
 * 19/02/2018
 *
 * @see <a href="http://www.tinmegali.com">tinmegali.com</a>
 * @see <a href="http://github.com/tinmegali">github</a>
 * ___________________________________
 */

public class MKeyWrapperForTests extends MKeyWrapper {

    @Override
    public void wrapAndStoreKey(@NonNull Context context, @NonNull SecretKey keyToWrap, @NonNull Key keyToWrapWith, @NonNull String alias) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, UnrecoverableKeyException, KeyStoreException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
        super.wrapAndStoreKey(context, keyToWrap, keyToWrapWith, alias);
    }

    @Override
    public void storeKey(Context context, String wrappedKey, String alias) {
        super.storeKey(context, wrappedKey, alias);
    }

    @Override
    public SecretKey loadWrappedBCKey(@NonNull Context context, @NonNull Key wrapperKey, @NonNull String alias) throws UnrecoverableKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, KeyWrapperException, IOException, ClassNotFoundException {
        return super.loadWrappedBCKey(context, wrapperKey, alias);
    }

    @Override
    public byte[] wrapKey(@NonNull Key keyToWrap, @NonNull Key keyToWrapWith) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, IOException {
        return super.wrapKey(keyToWrap, keyToWrapWith);
    }

    @Override
    public Key unWrapKey(@NonNull byte[] wrappedObj, @NonNull Key keyToUnWrap) throws NoSuchPaddingException, IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        return super.unWrapKey(wrappedObj, keyToUnWrap);
    }
}

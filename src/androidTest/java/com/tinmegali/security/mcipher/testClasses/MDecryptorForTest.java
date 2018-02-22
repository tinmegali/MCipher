package com.tinmegali.security.mcipher.testClasses;

import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.tinmegali.security.mcipher.MDecryptor;
import com.tinmegali.security.mcipher.exceptions.DecryptorException;
import com.tinmegali.security.mcipher.exceptions.KeyWrapperException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * com.tinmegali.security.mcipher.testClasses | MCipher
 * __________________________________
 * Created by tinmegali
 * 20/02/2018
 *
 * @see <a href="http://www.tinmegali.com">tinmegali.com</a>
 * @see <a href="http://github.com/tinmegali">github</a>
 * ___________________________________
 */

public class MDecryptorForTest extends MDecryptor {

    public MDecryptorForTest( String alias ) throws DecryptorException {
        super( alias );
    }

    @Override
    public void initKeyStore() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        super.initKeyStore();
    }

    @NonNull
    @Override
    public byte[] decrypt(@NonNull byte[] encryptedData, @Nullable Context context) throws DecryptorException {
        return super.decrypt(encryptedData, context);
    }

    @NonNull
    @Override
    public byte[] decryptLargeData(byte[] encryptedData, Context context) throws DecryptorException {
        return super.decryptLargeData(encryptedData, context);
    }

    @NonNull
    @Override
    public byte[] decryptData(@NonNull byte[] ecryptedData, @NonNull Cipher cipher) throws UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnrecoverableEntryException, KeyStoreException, NoSuchProviderException {
        return super.decryptData(ecryptedData, cipher);
    }

    @NonNull
    @Override
    protected Cipher getCipher(@NonNull String alias, @Nullable byte[] encryptionIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, DecryptorException, NoSuchProviderException {
        return super.getCipher(alias, encryptionIV);
    }

    @Override
    public SecretKey getSecretKey(String alias) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException {
        return super.getSecretKey(alias);
    }

    @Override
    public KeyPair getKeyPair(String alias) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, DecryptorException {
        return super.getKeyPair(alias);
    }

    @Override
    public Cipher wrapperCipher(@NonNull String alias, @NonNull Context context, byte[] cipherIV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchProviderException, KeyStoreException, IllegalBlockSizeException, DecryptorException, KeyWrapperException, IOException, ClassNotFoundException {
        return super.wrapperCipher(alias, context, cipherIV);
    }

    @Override
    public SecretKey getUnwrappedBCKey(@NonNull String alias, @NonNull Context context) throws NoSuchPaddingException, UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException, IllegalBlockSizeException, DecryptorException, KeyWrapperException, IOException, ClassNotFoundException {
        return super.getUnwrappedBCKey(alias, context);
    }
}

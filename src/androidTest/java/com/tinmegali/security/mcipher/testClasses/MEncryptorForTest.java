package com.tinmegali.security.mcipher.testClasses;

import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.tinmegali.security.mcipher.Constants;
import com.tinmegali.security.mcipher.MEncryptor;
import com.tinmegali.security.mcipher.exceptions.EncryptorException;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
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
 * 19/02/2018
 *
 * @see <a href="http://www.tinmegali.com">tinmegali.com</a>
 * @see <a href="http://github.com/tinmegali">github</a>
 * ___________________________________
 */

public class MEncryptorForTest extends MEncryptor {

    public String ALIAS_STANDARD = Constants.ALIAS_STANDARD_DATA;
    public String ALIAS_LARGE = Constants.ALIAS_LARGE_DATA;

    public MEncryptorForTest() throws EncryptorException {
        super();
    }

    @Override
    public void initKeyStore() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        super.initKeyStore();
    }

    @Override
    public KeyPair generateKeyPair(String alias, Context context) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        return super.generateKeyPair(alias, context);
    }

    @Override
    public byte[] encrypt(@NonNull String textToEncrypt, @Nullable Context context) throws EncryptorException {
        return super.encrypt(textToEncrypt, context);
    }

    @Override
    public byte[] encryptLargeData(@NonNull String dataToEncrypt, @NonNull Context context) throws EncryptorException {
        return super.encryptLargeData(dataToEncrypt, context);
    }

    @Override
    public byte[] encrypting(byte[] toEncrypt, Cipher cipher) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException, InvalidAlgorithmParameterException, SignatureException, BadPaddingException, IllegalBlockSizeException {
        return super.encrypting(toEncrypt, cipher);
    }

    @Override
    public Cipher cipherForEncrypt(@NonNull String alias, @Nullable Context context)
            throws EncryptorException {
        return super.cipherForEncrypt(alias, context);
    }

    @Override
    public SecretKey getSecretKey(String alias) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, KeyStoreException, UnrecoverableKeyException {
        return super.getSecretKey(alias);
    }

    @Override
    public SecretKey generateSecretKey(String alias) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, KeyStoreException, UnrecoverableKeyException {
        return super.generateSecretKey(alias);
    }

    @Override
    public KeyPair getKeyPair(@NonNull String alias, @NonNull Context context) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, InvalidAlgorithmParameterException {
        return super.getKeyPair(alias, context);
    }

    @Override
    public Cipher cipherLargeData(@NonNull String alias, @NonNull Context context, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnrecoverableKeyException, InvalidAlgorithmParameterException, NoSuchProviderException, KeyStoreException, IllegalBlockSizeException, IOException, ClassNotFoundException {
        return super.cipherLargeData(alias, context, iv);
    }

    @Override
    public SecretKey getBCSecretKey(@NonNull String alias, @NonNull Context context) throws NoSuchPaddingException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException, IllegalBlockSizeException, IOException, ClassNotFoundException {
        return super.getBCSecretKey(alias, context);
    }

    @Override
    public SecretKey generateBCSecretKey(Context context) throws NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException, KeyStoreException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        return super.generateBCSecretKey(context);
    }

    @Override
    public void wrapAndStoreBCKey(Context context, SecretKey bcKey) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, UnrecoverableKeyException, KeyStoreException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
        super.wrapAndStoreBCKey(context, bcKey);
    }
}

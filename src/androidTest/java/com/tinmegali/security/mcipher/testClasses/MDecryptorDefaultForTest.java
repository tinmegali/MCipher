package com.tinmegali.security.mcipher.testClasses;

import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.tinmegali.security.mcipher.MDecryptorDefault;
import com.tinmegali.security.mcipher.exceptions.MDecryptorException;
import com.tinmegali.security.mcipher.exceptions.MKeyWrapperException;

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

public class MDecryptorDefaultForTest extends MDecryptorDefault {

    public MDecryptorDefaultForTest(String alias ) throws MDecryptorException {
        super( alias );
        try {
            initKeyStore();
        } catch (CertificateException | NoSuchAlgorithmException
                | IOException | KeyStoreException e) {
            String errorMsg =
                    String.format("Something went wrong while initiating the KeyStore." +
                            "%n\t%s", e.getMessage());
            throw new MDecryptorException( errorMsg, e );
        }
    }

    @Override
    public void initKeyStore() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        super.initKeyStore();
    }

    @NonNull
    @Override
    public byte[] decrypt(@NonNull byte[] encryptedData, @Nullable Context context) throws MDecryptorException {
        return super.decrypt(encryptedData, context);
    }

    @NonNull
    @Override
    public byte[] decryptLargeData(byte[] encryptedData, Context context) throws MDecryptorException {
        return super.decryptLargeData(encryptedData, context);
    }

    @Override
    public byte[] decryptWithStream(byte[] toDecrypt, Cipher cipher) throws IOException {
        return super.decryptWithStream(toDecrypt, cipher);
    }

    @NonNull
    @Override
    public byte[] decryptData(@NonNull byte[] ecryptedData, @NonNull Cipher cipher) throws UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnrecoverableEntryException, KeyStoreException, NoSuchProviderException {
        return super.decryptData(ecryptedData, cipher);
    }

    @NonNull
    @Override
    protected Cipher getCipher(@NonNull String alias, @Nullable byte[] encryptionIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, MDecryptorException, NoSuchProviderException {
        return super.getCipher(alias, encryptionIV);
    }

    @Override
    public SecretKey getSecretKey(String alias) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException {
        return super.getSecretKey(alias);
    }

    @Override
    public KeyPair getKeyPair(String alias) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, MDecryptorException {
        return super.getKeyPair(alias);
    }

    @Override
    public Cipher wrapperCipher(@NonNull String alias, @NonNull Context context, byte[] cipherIV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchProviderException, KeyStoreException, IllegalBlockSizeException, MDecryptorException, MKeyWrapperException, IOException, ClassNotFoundException {
        return super.wrapperCipher(alias, context, cipherIV);
    }

    @Override
    public SecretKey getUnwrappedLargeKey(@NonNull String alias, @NonNull Context context) throws NoSuchPaddingException, UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException, IllegalBlockSizeException, MDecryptorException, MKeyWrapperException, IOException, ClassNotFoundException {
        return super.getUnwrappedLargeKey(alias, context);
    }
}

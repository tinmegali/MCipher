package com.tinmegali.security.mcipher;

/**
 * com.tinmegali.security.mcipher | MCipher
 * __________________________________
 * Created by tinmegali
 * 19/02/2018
 *
 * @see <a href="http://www.tinmegali.com">tinmegali.com</a>
 * @see <a href="http://github.com/tinmegali">github</a>
 * ___________________________________
 */

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.test.runner.AndroidJUnit4;
import android.util.Base64;

import com.tinmegali.security.mcipher.testClasses.MEncryptorForTest;
import com.tinmegali.security.mcipher.testClasses.MKeyWrapperForTests;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.Key;
import java.security.KeyPair;

import javax.crypto.SecretKey;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class KeyWrapperTests extends MCipherTestsBase {

    MKeyWrapper wrapper;
    MEncryptor enc;

    @Before
    public void setup() throws Exception {
        super.setup();
        wrapper = new MKeyWrapperForTests();
        enc = new MEncryptorForTest();
    }

    @Test
    public void wrapAndStore() throws Exception {

        String wrapped = getWrappedKey();

        wrapper.storeKey( appContext, wrapped );

        SharedPreferences pref = appContext
                .getSharedPreferences( Constants.PREFS_NAME,
                        Context.MODE_PRIVATE );

        String loadedWrapped = pref.getString( Constants.WRAPPED_KEY, null );
        assertNotNull( "Loaded Wrapped Key NULL", loadedWrapped );
        assertTrue( wrapped.equals( loadedWrapped ) );
    }

    @Test
    public void unwrap() throws Exception {

        String wrapped = getWrappedKey();
        Key wrapperKey = getDecryptionWrapperKey();
        assertNotNull( "UnWrapper Key NULL", wrapperKey );

        // FIXME use MCipherUtils to decode and encode
        byte[] wrappedData = Base64.decode( wrapped, Base64.DEFAULT );

        Key unwrapped = wrapper.unWrapKey( wrappedData, wrapperKey );
        assertNotNull( "UnWrapped key proccess didn't work", unwrapped );

    }

    @Test
    public void storeAndLoad() throws Exception {

        SecretKey bcKey = enc.generateBCSecretKey( appContext );
        assertNotNull( bcKey );
        Key encryptionKey = getEncryptionWrapperKey();
        assertNotNull( "UnWrapper Key NULL", encryptionKey );

        wrapper.wrapAndStoreKey( appContext, bcKey, encryptionKey);

        Key decryptionKey = getDecryptionWrapperKey();
        SecretKey loadedBcKey = wrapper.loadWrappedBCKey( appContext, decryptionKey );
        assertNotNull( loadedBcKey );

    }

    @NonNull
    private String getWrappedKey() throws Exception {
        Key wrapperKey = getEncryptionWrapperKey();

        SecretKey bcKey = enc.generateBCSecretKey( appContext );
        assertNotNull("Null BCSecretKey", bcKey );

        byte[] wrapped = wrapper.wrapKey( bcKey, wrapperKey );
        assertNotNull( "Wrapped Key null", wrapped );

        // FIXME use MCipherUtils to decode and encode
        return Base64.encodeToString( wrapped, Base64.DEFAULT );
    }

    private Key getEncryptionWrapperKey() throws Exception {
        if (Build.VERSION.SDK_INT < 23 ) {
            KeyPair pair = enc.getKeyPair( enc.ALIAS_LARGE, appContext );
            assertNotNull( "Null RSA KeyPair", pair);
            return pair.getPublic();
        } else {
            Key key = enc.getSecretKey( enc.ALIAS_STANDARD );
            assertNotNull( "Null SecretKey", key );
            return key;
        }
    }

    private Key getDecryptionWrapperKey() throws Exception {
        if (Build.VERSION.SDK_INT < 23 ) {
            KeyPair pair = enc.getKeyPair( enc.ALIAS_LARGE, appContext );
            assertNotNull( "Null RSA KeyPair", pair);
            return pair.getPrivate();
        } else {
            Key key = enc.getSecretKey( enc.ALIAS_STANDARD );
            assertNotNull( "Null SecretKey", key );
            return key;
        }
    }

}

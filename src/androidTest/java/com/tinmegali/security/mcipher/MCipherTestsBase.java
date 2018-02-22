package com.tinmegali.security.mcipher;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.tinmegali.security.mcipher.testClasses.MEncryptorForTest;

import org.junit.After;
import org.junit.Before;
import org.junit.runner.RunWith;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Enumeration;

import static org.junit.Assert.assertNotNull;

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

@RunWith(AndroidJUnit4.class)
public class MCipherTestsBase {

    public static final String ALIAS = "com.tinmegali.security.cipher._test_key";

    protected final String s1 = "a string";
    protected final String s2 = "kahsdkjhakjsdhakjshdkjahdkjahskjdhaskjdhakjsdhaskdh";
    protected final String s3 = "kahsdkjhakjsdhakjshdk jahdkjahsk jdhaskjdhakjsdhaskdslks lkdlkjfkjfkgjdkfhgkjdhfkgjhdkfjghkdfjhgkjhieuhriuehi ehrgiuehrighergh";
    protected final String s4 = s3 + s3 + s3 + s3;
    protected Context appContext;
    protected KeyStore keyStore;
    protected SharedPreferences prefs;

    @Before
    public void setup() throws Exception {
        appContext = InstrumentationRegistry.getTargetContext();
        keyStore = KeyStore.getInstance( KeyStore.getDefaultType() );
        keyStore.load( null );
        deleteKeys();
        prefs = appContext.getSharedPreferences( Constants.PREFS_NAME, Context.MODE_PRIVATE );
        deleteSavedKeys();
    }

    @After
    public void cleanup() throws Exception {
        deleteKeys();
        deleteSavedKeys();
    }

    protected void deleteKeys() throws KeyStoreException {
        Enumeration<String> aliases = keyStore.aliases();
        while ( aliases.hasMoreElements() ) {
            String alias = aliases.nextElement();
            keyStore.deleteEntry( alias );
        }
    }

    protected void deleteSavedKeys() {
        SharedPreferences.Editor editor = prefs.edit();
        editor.remove( Constants.WRAPPED_KEY );
        editor.commit();
    }

}

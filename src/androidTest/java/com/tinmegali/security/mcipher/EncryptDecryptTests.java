package com.tinmegali.security.mcipher;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.tinmegali.security.mcipher.exceptions.DecryptorException;
import com.tinmegali.security.mcipher.exceptions.EncryptorException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class EncryptDecryptTests {

    final String ALIAS_STANDARD_DATA    = "com.tinmegali.security.cipher.standard";
    final String ALIAS_LARGE_DATA       = "com.tinmegali.security.cipher.large";
    final String s1 = "a string";
    final String s2 = "kahsdkjhakjsdhakjshdkjahdkjahskjdhaskjdhakjsdhaskdh";
    final String s3 = "kahsdkjhakjsdhakjshdk jahdkjahsk jdhaskjdhakjsdhaskdslks lkdlkjfkjfkgjdkfhgkjdhfkgjhdkfjghkdfjhgkjhieuhriuehi ehrgiuehrighergh";
    final String s4 = s3 + s3 + s3 + s3;
    Context appContext;
    MEncryptor enc;
    MDecryptor dec;

    @Before
    public void setup() throws Exception {
        appContext = InstrumentationRegistry.getTargetContext();
        enc = new MEncryptor();
        dec = new MDecryptor();
    }

    @Test
    public void encryptDecrypt() throws Exception {

        encryptDecryptStr(s1 );
        encryptDecryptStr(s2);
        encryptDecryptStr(s3);
        encryptDecryptStr(s4);

    }

    private void encryptDecryptStr(String s)
            throws EncryptorException, DecryptorException {
        byte[] encrypted = enc.encrypt( s, appContext );
        assertNotNull( encrypted );

        byte[] decrypted = dec.decrypt( encrypted );
        String decryptedStr = MCipherUtils.encodeToStr( decrypted );
        assertNotNull( decrypted );
        assertTrue( String.format("%s\n%s",s,decryptedStr), s.equals( decryptedStr ) );
    }

    @Test
    public void encryptDecryptLargeTest() throws Exception {
        encryptDecyptLarge( s1 );
        encryptDecyptLarge( s2 );
        encryptDecyptLarge( s3 );
        encryptDecyptLarge( s4 );
    }

    private void encryptDecyptLarge( String s)
            throws EncryptorException, DecryptorException
    {
        byte[] encrypted = enc.encryptLargeData( s, appContext );
        assertNotNull( encrypted );

        byte[] decrypted = dec.decryptLargeData( encrypted, appContext );
        assertNotNull( decrypted );

        String decryptedS = MCipherUtils.encodeToStr( decrypted );
        assertTrue( String.format("%s\n%s",s,decryptedS), s.equals( decryptedS ) );
    }
}

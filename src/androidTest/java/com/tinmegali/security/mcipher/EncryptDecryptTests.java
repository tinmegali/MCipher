package com.tinmegali.security.mcipher;

import android.content.Context;
import android.os.Build;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.tinmegali.security.mcipher.exceptions.DecryptorException;
import com.tinmegali.security.mcipher.exceptions.EncryptorException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;

import static org.junit.Assert.*;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class EncryptDecryptTests {

    final String s1 = "a string";
    final String s2 = "kahsdkjhakjsdhakjshdkjahdkjahskjdhaskjdhakjsdhaskdh";
    final String s3 = "kahsdkjhakjsdhakjshdk jahdkjahsk jdhaskjdhakjsdhaskdslks lkdlkjfkjfkgjdkfhgkjdhfkgjhdkfjghkdfjhgkjhieuhriuehi ehrgiuehrighergh";
    final String sLarge = s3 + s3 + s3 + s3;
    Context appContext;
    MEncryptor enc;
    MDecryptor dec;

    @Before
    public void setup() throws Exception {
        appContext = InstrumentationRegistry.getTargetContext();
        enc = new MEncryptor( MCipherTestsBase.ALIAS );
        dec = new MDecryptor( MCipherTestsBase.ALIAS );
    }

    @Test
    public void encryptDecrypt() throws Exception {

        encryptDecryptStr(s1 );
        encryptDecryptStr(s2);
        encryptDecryptStr(s3);
        if (Build.VERSION.SDK_INT >= 23) {
            encryptDecryptStr( sLarge );
        }

    }

    private void encryptDecryptStr(String s)
            throws EncryptorException, DecryptorException, IOException, ClassNotFoundException {
        byte[] encrypted = enc.encrypt( s, appContext );
        assertNotNull( encrypted );

        byte[] decrypted = dec.decrypt( encrypted, appContext );
        String decryptedStr = MCipherUtils.encodeToStr( decrypted );
        assertNotNull( decrypted );
        assertTrue( String.format("%s\n%s",s,decryptedStr), s.equals( decryptedStr ) );
    }

    @Test
    public void encryptDecryptLargeTest() throws Exception {
        encryptDecyptLarge( s1 );
        encryptDecyptLarge( s2 );
        encryptDecyptLarge( s3 );
        encryptDecyptLarge(sLarge);
    }

    private void encryptDecyptLarge( String s)
            throws EncryptorException, DecryptorException, IOException, ClassNotFoundException {
        byte[] encrypted = enc.encryptLargeData( s, appContext );
        assertNotNull( encrypted );
        MEncryptedObject encObj = MEncryptedObject.getEncryptedObject( encrypted );
        assertNotNull( encObj.getData() );
        assertNotNull( encObj.getCypherIV() );

        byte[] decrypted = dec.decryptLargeData( encrypted, appContext );
        assertNotNull( decrypted );
        String resultStr = MCipherUtils.encodeToStr( decrypted );
        assertNotNull( resultStr );
        assertTrue( String.format("%s\n%s",s,resultStr), s.equals( resultStr ) );
    }
}

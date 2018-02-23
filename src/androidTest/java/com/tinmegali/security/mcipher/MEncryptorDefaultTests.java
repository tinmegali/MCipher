package com.tinmegali.security.mcipher;

import android.os.Build;
import android.support.annotation.RequiresApi;
import android.support.test.runner.AndroidJUnit4;

import com.tinmegali.security.mcipher.testClasses.MEncryptorDefaultForTest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import static org.junit.Assert.*;

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
public class MEncryptorDefaultTests extends MCipherTestsBase {

    private MEncryptorDefaultForTest enc;

    @Before
    public void setup() throws Exception {
        super.setup();
        enc = new MEncryptorDefaultForTest( MCipherTestsBase.ALIAS );
        assertNotNull( enc );
    }

    @After
    @Override
    public void cleanup() throws Exception {
        super.cleanup();
    }

    @Test
    public void generateKeyPair() throws Exception {
        if ( Build.VERSION.SDK_INT < 23 ) {
            KeyPair pair = enc.generateKeyPair( MCipherTestsBase.ALIAS, appContext);
            assertPair(pair);
            pair = enc.generateKeyPair(MCipherTestsBase.ALIAS_LARGE, appContext);
            assertPair(pair);
        }
    }

    @Test
    public void getKeyPair() throws Exception {
        if ( Build.VERSION.SDK_INT < 23 ) {
            KeyPair generatedPair = enc.getKeyPair(MCipherTestsBase.ALIAS, appContext);
            assertPair(generatedPair);

            KeyPair loadedPair = enc.getKeyPair(MCipherTestsBase.ALIAS, appContext);
            assertPair(loadedPair);

            assertTrue(loadedPair.getPublic().equals(generatedPair.getPublic()));
            assertTrue(loadedPair.getPrivate().equals(generatedPair.getPrivate()));

            generatedPair = enc.getKeyPair(MCipherTestsBase.ALIAS_LARGE, appContext);
            assertPair(generatedPair);

            loadedPair = enc.getKeyPair(MCipherTestsBase.ALIAS_LARGE, appContext);
            assertPair(loadedPair);

            assertTrue(loadedPair.getPublic().equals(generatedPair.getPublic()));
            assertTrue(loadedPair.getPrivate().equals(generatedPair.getPrivate()));
        }

    }

    @Test
    @RequiresApi(api = Build.VERSION_CODES.M)
    public void generateSecretKey() throws Exception {
        if( Build.VERSION.SDK_INT > 23) {
            SecretKey key = enc.generateSecretKey(MCipherTestsBase.ALIAS);
            assertNotNull(key);
        }
    }

    @Test
    @RequiresApi( api = Build.VERSION_CODES.M)
    public void getSecretKey() throws Exception {
        if ( Build.VERSION.SDK_INT > 23 ) {
            SecretKey key = enc.getSecretKey( MCipherTestsBase.ALIAS );
            assertNotNull(key);

            key = enc.getSecretKey( MCipherTestsBase.ALIAS_LARGE );
            assertNotNull(key);
        }
    }

    @Test
    public void generateBCSecretKey() throws Exception {
        SecretKey key = enc.generateSecretKeyForLargeOps( appContext );
        assertNotNull( key );
    }

    @Test
    public void getBCSecretKey() throws Exception {
        String alias;
        if (Build.VERSION.SDK_INT < 23)
        {
            alias = MCipherTestsBase.ALIAS_LARGE;
        }
        else //SDK 23+
        {
            alias = MCipherTestsBase.ALIAS;
        }

        SecretKey generatedBCKey = enc.getLargeSecretKey( alias, appContext );
        assertNotNull( "Bouncy Castle Key wasn't generated correctly", generatedBCKey );

        SecretKey loadedBCKey = enc.getLargeSecretKey( alias, appContext );
        assertNotNull( "Bouncy Castle Key wasn't loaded correctly", loadedBCKey );

    }

    @Test
    public void encryptLarge() throws Exception {
        if ( Build.VERSION.SDK_INT < 23 ) {
            byte[] d4 = enc.encrypt(MCipherUtils.decode(s4), appContext);
            assertEncryption(d4);

            byte[] iv = MCipherUtils.generateIV();
            assertNotNull(iv);
            Cipher cipher = enc.cipherLargeData(MCipherTestsBase.ALIAS_LARGE, appContext, iv);
            assertNotNull(cipher);

            byte[] toEncrypt = MCipherUtils.decode(s4);
            byte[] encryptedData = cipher.doFinal(toEncrypt);

            byte[] encryptedObj = MEncryptedObject.serializeEncryptedObj(encryptedData, iv);

            assertNotNull(encryptedObj);

            MEncryptedObject obj = MEncryptedObject.getEncryptedObject(encryptedObj);
            assertNotNull(obj.getData());
            assertTrue(Arrays.equals(obj.getData(), encryptedData));
            assertNotNull(obj.getCypherIV());
            assertTrue(Arrays.equals(obj.getCypherIV(), iv));
        }
    }

//    @Test
    public void discoverBlockLimitForEncryption() throws Exception {
        // during tests, the limit was 4073
        StringBuilder s = new StringBuilder(s4);
        int size = 0;
        try {
            for (; ; ) {
                s.append("s");
                byte[] data = s.toString().getBytes("UTF-8");
                size = data.length;
                System.out.println("Size: " + size);
                Cipher cipher = enc.cipherForEncrypt("alias", appContext);

                byte[] encrypted = cipher.doFinal(data);
                assertNotNull(encrypted);

            }
        } catch (IllegalBlockSizeException e) {
            System.out.println("Illegal size: " + size);
        }

    }

    @Test
    public void encryptRealLargeStrings() throws Exception {
        if ( Build.VERSION.SDK_INT >= 23 ) {
        Cipher cipher = Cipher.getInstance( MCipherConstants.TRANSFORMATION );
            SecretKey key = enc.generateSecretKey("alias");
            cipher.init(Cipher.ENCRYPT_MODE, key);
        assertNotNull(cipher);

        InputStream in = new ByteArrayInputStream( bigText.getBytes("UTF-8") );
        CipherInputStream cipherIn = new CipherInputStream( in, cipher );

        // making the encryption
        ArrayList<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherIn.read()) != -1) {
            values.add((byte) nextByte);
        }

        // recovering the encrypted data
        byte[] encryptedData = new byte[values.size()];
        for (int i = 0; i < encryptedData.length; i++) {
            encryptedData[i] = values.get(i);
        }
        assertNotNull( encryptedData );

        byte[] encryptedObj = MEncryptedObject.serializeEncryptedObj(encryptedData, cipher.getIV());

        assertNotNull(encryptedObj);

        MEncryptedObject obj = MEncryptedObject.getEncryptedObject(encryptedObj);
        assertNotNull(obj.getData());
        assertTrue(Arrays.equals(obj.getData(), encryptedData));
        assertNotNull(obj.getCypherIV());
        assertTrue(Arrays.equals(obj.getCypherIV(), cipher.getIV()));

        cipher = enc.cipherForEncrypt( "alias", appContext );
        encryptedObj = enc.encryptWithStream( bigText.getBytes("UTF-8"), cipher );
        assertNotNull( encryptedObj );


        encryptedObj = enc.encrypt( bigText, appContext );
        assertNotNull( encryptedObj );
        }

    }

    @Test
    public void encrypt() throws Exception {
        byte[] d1 = enc.encrypt( s1, appContext );
        assertEncryption(d1);

        byte[] d2 = enc.encrypt( s2, appContext );
        assertEncryption(d2);

        byte[] d3 = enc.encrypt( s3, appContext );
        assertEncryption(d3);

        byte[] d4 = enc.encrypt( s4, appContext );
        assertEncryption(d4);

    }

    private void assertEncryption(byte[] d1) throws IOException, ClassNotFoundException {
        assertNotNull( d1 );
        MEncryptedObject obj1 = MEncryptedObject.getEncryptedObject( d1 );
        assertNotNull( obj1 );
        assertNotNull( obj1.getData() );
        if ( Build.VERSION.SDK_INT >= 23 )
            assertNotNull( obj1.getCypherIV() );
    }

    private void assertPair(KeyPair pair) {
        assertNotNull( pair );
        assertNotNull( pair.getPrivate() );
        assertNotNull( pair.getPublic() );
    }

    @Test
    public void getCipher() throws Exception {
        Cipher cipher = enc.cipherForEncrypt( MCipherTestsBase.ALIAS, appContext );
        assertNotNull( "Cipher cannot be null", cipher );

        if ( Build.VERSION.SDK_INT >= 23 )
            assertNotNull( cipher.getIV() );
        else
            assertNull( cipher.getIV() );

        if ( Build.VERSION.SDK_INT < 23 ) {
            cipher = enc.cipherForEncrypt(MCipherTestsBase.ALIAS_LARGE, appContext);
            assertNotNull("Cipher cannot be null", cipher);
        }
    }

    @Test
    public void getCipherLarge() throws Exception {
        if ( Build.VERSION.SDK_INT < 23 ) {
            byte[] iv = MCipherUtils.generateIV();
            Cipher cipher = enc.cipherLargeData(MCipherTestsBase.ALIAS_LARGE, appContext, iv);
            assertNotNull(cipher);
            assertNotNull(cipher.getIV());
        }
    }

}

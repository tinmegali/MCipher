package com.tinmegali.security.mcipher;

import android.os.Build;
import android.support.test.runner.AndroidJUnit4;

import com.tinmegali.security.mcipher.testClasses.MDecryptorForTest;
import com.tinmegali.security.mcipher.testClasses.MEncryptorForTest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.KeyPair;
import java.security.Provider;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import static org.junit.Assert.*;

/**
 * com.tinmegali.security.mcipher | MCipher
 * __________________________________
 * Created by tinmegali
 * 20/02/2018
 *
 * @see <a href="http://www.tinmegali.com">tinmegali.com</a>
 * @see <a href="http://github.com/tinmegali">github</a>
 * ___________________________________
 */

@RunWith(AndroidJUnit4.class)
public class MDecryptorTests extends MCipherTestsBase {

    MDecryptor dec;
    MEncryptor enc;

    byte[] e1,e2,e3,e4;


    @Before
    public void setup() throws Exception {
        super.setup();
        enc = new MEncryptorForTest( MCipherTestsBase.ALIAS );
        assertNotNull( enc );

        dec = new MDecryptorForTest( MCipherTestsBase.ALIAS );
        assertNotNull( dec );

        encryptString();
    }

    @After
    @Override
    public void cleanup() throws Exception {
        super.cleanup();
    }

    private void encryptString() throws Exception {
        e1 = enc.encrypt( s1, appContext );
        e2 = enc.encrypt( s2, appContext );
        e3 = enc.encrypt( s3, appContext );
        e4 = enc.encryptLargeData( s4, appContext );
    }

    @Test
    public void getKeyPair() throws Exception {
        if ( !isVersion23Up() ) {
            KeyPair pair = dec.getKeyPair( Constants.ALIAS_STANDARD_DATA );
            assertNotNull( pair );
        }
    }

    @Test
    public void getSecretKey() throws Exception {
        if ( isVersion23Up() ) {
            SecretKey key = dec.getSecretKey( Constants.ALIAS_STANDARD_DATA );
            assertNotNull( key );
        }
    }

    @Test
    public void getBCSecretKey() throws Exception {
        if ( !isVersion23Up() ) {
            String alias = Constants.ALIAS_LARGE_DATA;

            deleteSavedKeys();
            SecretKey originalKey = enc.getBCSecretKey( Constants.ALIAS_STANDARD_DATA, appContext );

            SecretKey bcKey = dec.getUnwrappedBCKey(alias, appContext);
            assertNotNull(bcKey);
            assertEquals( bcKey.hashCode(), originalKey.hashCode() );
        }
    }

    @Test
    public void cipher() throws Exception {
        MEncryptedObject obj = MEncryptedObject.getEncryptedObject( e1 );
        Cipher cipher = dec.getCipher( Constants.ALIAS_STANDARD_DATA, obj.getCypherIV() );
        assertNotNull( "Cipher is null", cipher );
        assertEquals( "Wrong algorithm", cipher.getAlgorithm(), Constants.TRANSFORMATION );
        if ( Build.VERSION.SDK_INT < 23 ) {
            assertNull( cipher.getIV() );
        } else {
            assertNotNull( cipher.getIV() );
            assertTrue( "VectorIV doesn't match",
                    Arrays.equals( cipher.getIV(), obj.getCypherIV() ));
        }
    }

    @Test
    public void decrypt() throws Exception {

        byte[] d1 = dec.decrypt(e1, appContext);
        assertDecryption(d1, s1);

        byte[] d2 = dec.decrypt(e2, appContext);
        assertDecryption(d2, s2);

        byte[] d3 = dec.decrypt(e3, appContext);
        assertDecryption(d3, s3);

        byte[] d4 = dec.decrypt(e4, appContext);
        assertDecryption(d4, s4);

    }

    @Test
    public void decryptLarge() throws Exception {
        deleteSavedKeys();

        byte[] encryptedObj = enc.encryptLargeData( s4, appContext );
        assertNotNull( encryptedObj );
        byte[] decryptedObj = dec.decryptLargeData( encryptedObj, appContext );
        assertNotNull( decryptedObj );

    }

    @Test
    public void decryptLargeSteps() throws Exception {
        deleteSavedKeys();

        byte[] encryptedObj = enc.encryptLargeData( s4, appContext );

        assertNotNull( encryptedObj );

        MEncryptedObject obj = MEncryptedObject.getEncryptedObject( encryptedObj );
        assertNotNull( obj.getData() );
        assertNotNull( obj.getCypherIV() );

        Cipher cipherDec = Cipher.getInstance( Constants.TRANSFORMATION_BC );
        SecretKey bcKey = dec.getUnwrappedBCKey( Constants.ALIAS_LARGE_DATA, appContext );
        IvParameterSpec specs = new IvParameterSpec( obj.getCypherIV() );
        cipherDec.init( Cipher.DECRYPT_MODE, bcKey, specs );
        assertNotNull( cipherDec );
        assertTrue( Arrays.equals( cipherDec.getIV(), obj.getCypherIV() ) );

        byte[] decrypted = cipherDec.doFinal( obj.getData() );
        assertNotNull( decrypted );
    }

    private void assertDecryption(byte[] decrypted, String original) {
        assertNotNull( decrypted );
        String d1S = MCipherUtils.encodeToStr( decrypted );

        assertTrue( String.format(
                "Encrypted and decrypted doesn't match." +
                        "\n\tOriginal: %s" +
                        "\n\tEncrypted: %s",
                original, d1S ),
                d1S.equals( original ) );
    }

    @Test
    public void wrapperCipher() throws Exception {
        if ( !isVersion23Up() ) {
            e4 = enc.encryptLargeData( s4, appContext );
            byte[] cipherIV = MEncryptedObject.getEncryptedObject( e4 ).getCypherIV();
            Cipher cipher = dec.wrapperCipher( Constants.ALIAS_LARGE_DATA, appContext, cipherIV );
            assertNotNull( cipher );
            assertNotNull( cipher.getIV() );
            assertTrue( cipher.getAlgorithm().equals( Constants.TRANSFORMATION_BC ));
        }
    }

    private boolean isVersion23Up() {
        return Build.VERSION.SDK_INT >= 23;
    }

}

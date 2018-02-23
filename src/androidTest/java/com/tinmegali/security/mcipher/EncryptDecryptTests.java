package com.tinmegali.security.mcipher;

import android.content.Context;
import android.os.Build;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.tinmegali.security.mcipher.exceptions.MDecryptorException;
import com.tinmegali.security.mcipher.exceptions.MEncryptorException;

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
public class EncryptDecryptTests extends MCipherTestsBase {

    final String s1 = "a string";
    final String s2 = "kahsdkjhakjsdhakjshdkjahdkjahskjdhaskjdhakjsdhaskdh";
    final String s3 = "kahsdkjhakjsdhakjshdk jahdkjahsk jdhaskjdhakjsdhaskdslks lkdlkjfkjfkgjdkfhgkjdhfkgjhdkfjghkdfjhgkjhieuhriuehi ehrgiuehrighergh";
    final String sLarge = s3 + s3 + s3 + s3;
    MEncryptorDefault enc;
    MDecryptorDefault dec;

    @Before
    public void setup() throws Exception {
        super.setup();
        enc = new MEncryptorDefault( "alias-n" );
        enc.initKeyStore();
        dec = new MDecryptorDefault( "alias-n" );
        dec.initKeyStore();
    }

    @Test
    public void encryptDecrypt() throws Exception {

//        encryptDecryptStr(s1 );
//        encryptDecryptStr(s2);
//        encryptDecryptStr(s3);
        if (Build.VERSION.SDK_INT >= 23) {
//            encryptDecryptStr( sLarge );
            cleanup();
            deleteKeys();
            encryptDecryptStr( bigText );
        }

    }

    private void encryptDecryptStr(String s)
            throws MEncryptorException, MDecryptorException, IOException, ClassNotFoundException {
        byte[] encrypted = enc.encrypt( s, appContext );
        assertNotNull( encrypted );

        byte[] decrypted = dec.decrypt( encrypted, appContext );
        String decryptedStr = MCipherUtils.encodeToStr( decrypted );
        assertNotNull( decrypted );
        assertTrue( String.format("%s\n%s",s,decryptedStr), s.equals( decryptedStr ) );
    }

    @Test
    public void encryptDecryptLargeTest() throws Exception {
        encryptDecyptLarge(sLarge);
    }

    private void encryptDecyptLarge( String s)
            throws MEncryptorException, MDecryptorException, IOException, ClassNotFoundException {
        byte[] encrypted = enc.encrypt( s, appContext );
        assertNotNull( encrypted );
        MEncryptedObject encObj = MEncryptedObject.getEncryptedObject( encrypted );
        assertNotNull( encObj.getData() );
//        assertNotNull( encObj.getCypherIV() );

        byte[] decrypted = dec.decryptLargeData( encrypted, appContext );
        assertNotNull( decrypted );
        String resultStr = MCipherUtils.encodeToStr( decrypted );
        assertNotNull( resultStr );
        assertTrue( String.format("%s\n%s",s,resultStr), s.equals( resultStr ) );
    }

    String bigText =
            "The Android Keystore system lets you store cryptographic keys in a container to make it more difficult to extract from the device. Once keys are in the keystore, they can be used for cryptographic operations with the key material remaining non-exportable. Moreover, it offers facilities to restrict when and how keys can be used, such as requiring user authentication for key use or restricting keys to be used only in certain cryptographic modes. See Security Features section for more information.\n" +
                    "\n" +
                    "The Keystore system is used by the KeyChain API as well as the Android Keystore provider feature that was introduced in Android 4.3 (API level 18). This document goes over when and how to use the Android Keystore provider.\n" +
                    "" +
                    "Android Keystore system protects key material from unauthorized use. Firstly, Android Keystore mitigates unauthorized use of key material outside of the Android device by preventing extraction of the key material from application processes and from the Android device as a whole. Secondly, Android KeyStore mitigates unauthorized use of key material on the Android device by making apps specify authorized uses of their keys and then enforcing these restrictions outside of the apps' processes.\n" +
                    "" +
                    "Key material of Android Keystore keys is protected from extraction using two security measures:\n" +
                    "\n" +
                    "    Key material never enters the application process. When an application performs cryptographic operations using an Android Keystore key, behind the scenes plaintext, ciphertext, and messages to be signed or verified are fed to a system process which carries out the cryptographic operations. If the app's process is compromised, the attacker may be able to use the app's keys but will not be able to extract their key material (for example, to be used outside of the Android device).\n" +
                    "    Key material may be bound to the secure hardware (e.g., Trusted Execution Environment (TEE), Secure Element (SE)) of the Android device. When this feature is enabled for a key, its key material is never exposed outside of secure hardware. If the Android OS is compromised or an attacker can read the device's internal storage, the attacker may be able to use any app's Android Keystore keys on the Android device, but not extract them from the device. This feature is enabled only if the device's secure hardware supports the particular combination of key algorithm, block modes, padding schemes, and digests with which the key is authorized to be used. To check whether the feature is enabled for a key, obtain a KeyInfo for the key and inspect the return value of KeyInfo.isInsideSecurityHardware().\n" +
                    "\n" +
                    "" +
                    "To mitigate unauthorized use of keys on the Android device, Android Keystore lets apps specify authorized uses of their keys when generating or importing the keys. Once a key is generated or imported, its authorizations can not be changed. Authorizations are then enforced by the Android Keystore whenever the key is used. This is an advanced security feature which is generally useful only if your requirements are that a compromise of your application process after key generation/import (but not before or during) cannot lead to unauthorized uses of the key.\n" +
                    "\n" +
                    "Supported key use authorizations fall into the following categories:\n" +
                    "\n" +
                    "    cryptography: authorized key algorithm, operations or purposes (encrypt, decrypt, sign, verify), padding schemes, block modes, digests with which the key can be used;\n" +
                    "    temporal validity interval: interval of time during which the key is authorized for use;\n" +
                    "    user authentication: the key can only be used if the user has been authenticated recently enough. See Requiring User Authentication For Key Use.\n" +
                    "\n" +
                    "As an additional security measure, for keys whose key material is inside secure hardware (see KeyInfo.isInsideSecurityHardware()) some key use authorizations may be enforced by secure hardware, depending on the Android device. Cryptographic and user authentication authorizations are likely to be enforced by secure hardware. Temporal validity interval authorizations are unlikely to be enforced by the secure hardware because it normally does not have an independent secure real-time clock.\n" +
                    "\n" +
                    "Whether a key's user authentication authorization is enforced by the secure hardware can be queried using KeyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware().\n" +
                    "" +
                    "Use the KeyChain API when you want system-wide credentials. When an app requests the use of any credential through the KeyChain API, users get to choose, through a system-provided UI, which of the installed credentials an app can access. This allows several apps to use the same set of credentials with user consent.\n" +
                    "\n" +
                    "Use the Android Keystore provider to let an individual app store its own credentials that only the app itself can access. This provides a way for apps to manage credentials that are usable only by itself while providing the same security benefits that the KeyChain API provides for system-wide credentials. This method requires no user interaction to select the credentials.\n" +
                    "" +
                    " To use this feature, you use the standard KeyStore and KeyPairGenerator or KeyGenerator classes along with the AndroidKeyStore provider introduced in Android 4.3 (API level 18).\n" +
                    "\n" +
                    "AndroidKeyStore is registered as a KeyStore type for use with the KeyStore.getInstance(type) method and as a provider for use with the KeyPairGenerator.getInstance(algorithm, provider) and KeyGenerator.getInstance(algorithm, provider) methods.\n" +
                    "Generating a New Private Key\n" +
                    "\n" +
                    "Generating a new PrivateKey requires that you also specify the initial X.509 attributes that the self-signed certificate will have. You can use KeyStore.setKeyEntry to replace the certificate at a later time with a certificate signed by a Certificate Authority (CA).\n" +
                    "\n" +
                    "To generate the key, use a KeyPairGenerator with KeyPairGeneratorSpec:";



}

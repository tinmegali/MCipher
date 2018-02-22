# MCipher Library
###### A Simple Encryption and Decryption Library for Android
- VERSION 0.3
- [Documentation](https://tinmegali.github.io/MCipher/javadoc/)
- Compatible with from **SDK 19**

This simple library aims to reduce the overhead necessary to securely encrypt and decrypt files in the Android system.
It relies only in Android native libraries, making use of the [KeyStore](https://developer.android.com/training/articles/keystore.html),
combined with [SecretKeys](https://developer.android.com/reference/javax/crypto/SecretKey.html) or
[KeyPair](https://developer.android.com/reference/java/security/KeyPair.html) to make the encryption and decryption process.

The *MCipher* is currently in development process, but it is pretty stable so far. I tried to document the library
as detailed as I could. Check it out the [JavaDoc](https://tinmegali.github.io/MCipher/javadoc/).

If you have the time, any help to improve the tool will be welcomed.


## MCipher Advantages
- Compatible with SDK 19.
- Uses the best Android framework compatible with the SDK in use.
- Extremely simple to use.
- Relies only on Android native libraries.


# Using MCipher
The encryption and decryption process relies on two interfaces,
[MEncryptor](https://tinmegali.github.io/MCipher/javadoc/com/tinmegali/security/mcipher/MEncryptor.html)
and [MDecryptor](https://tinmegali.github.io/MCipher/javadoc/com/tinmegali/security/mcipher/MDecryptor.html).
All you have to do is build the interfaces,
providing a common 'alias' for both MEcnryptor and MDecryptor and you're good to go.

Keep in mind that it could be a good idea to make the encryption and decryption using background task,
otherwise your ui thread may be compromised.
```java
// a good idea is to use your package name as a foundation for the 'alias'
String ALIAS = "my.package.name.mcipher.alias"
MEncryptor encryptor = new MEncryptorBuilder( ALIAS ).build();
MDecryptor decryptor = new MDecryptorBuilder( ALIAS ).build();

String toEncrypt = "encrypt this string";
// encrypting
String encrypted = encryptor.encryptString( toEncrypt, this );

// decrypting
String decrypted = decryptor.decryptString( encrypted, this );
```

## Installation
You can download MCipher from *jcenter* directly.
Don't forget to point to *`jcenter`* distribution center.

###### Maven
```xml
<dependency>
    <groupId>com.tinmegali.android</groupId>
    <artifactId>mcipher</artifactId>
    <version>0.3</version>
    <type>pom</type>
</dependency>
```
###### Gradle
```
compile 'com.tinmegali.android:mcipher:0.3'
```
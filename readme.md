# MCipher Library
###### A Simple Encryption and Decryption Library for Android

- Compatible with from **SDK 19**
- Recommended to **SDK 23+**.
- VERSION 0.1

## Installing
Don't forget to point to *`jcenter`* distribution center.
###### Maven
```xml
<dependency>
    <groupId>com.tinmegali.android</groupId>
    <artifactId>mcipher</artifactId>
    <version>0.2</version>
    <type>pom</type>
</dependency>
```
###### Gradle
```
compile 'com.tinmegali.android:mcipher:0.2'
```

## Encrypting data
1. Instantiate and Initialize a `MEncryptor.class`.
2. Call `MEncryptor.encrypt( String dataToEncrypt, Context context )`.
3. You can convert the received `byte[]` to a `String` using the utility method `MCipherUtils.encodeToStr(byte[] data)`.
4. When running **MCipher on Android version previous to 23**, try to call `MEncryptor.encryptLargeData()` when trying to encrypt data with more than 240 symbols.

```java
MEncryptor encryptor;
//...
// initializing
private void initializeEncryptor()
{
    try {
        encryptor = new MEncryptor();
    }
    catch ( EncryptorException e )
    {
        String errorMsg = String.format("" +
            "Something went wrong while initializing the MEncryptor." +
            "%n\t Exception: [%s]" +
            "%n\t Cause: %s",
            e.getClass().getSimpleName(), e.getCause());
        Log.e(TAG, errorMsg);
        encryptor = null;
    }
}
//...
// encrypting some text
private void encryptData(String dataToEncrypt) {
    if ( !dataToEncrypt.isEmpty() || dataToEncrypt.length() > 0 )
    {
        try {
            encryptedData = encryptor.encrypt( dataToEncrypt, App.getContext() );
            // transforming encrypted byte array to String
            String encryptedStr = MCipherUtils.encodeToStr(encryptedData);
            saveEncryptedData( encryptedData );
            textFeedback.setText( encryptedStr );
        } catch (EncryptorException e) {
            Log.e(TAG, e.getMessage());
        }
    }
    else {
        Log.w(TAG, "Cannot encrypt empty text");
        String msg = "Type something before encrypting";
        textFeedback.setText( msg );
    }
}
```

## Decrypting data
1. Instantiate and Initialize a `MDecryptor.class`.
2. Call `MDecryptor.decrypt( final byte[] encryptedData )`.

```java
MDecryptor decryptor;
\\...
\\ initializing
private void initializeDecryptor()
{
    try {
        decryptor = new MDecryptor();
    }
    catch ( DecryptorException e )
    {
        String errorMsg = String.format("" +
            "Something went wrong while initializing the MDecryptor." +
            "%n\t Exception: [%s]" +
            "%n\t Cause: %s",
            e.getClass().getSimpleName(), e.getCause());
        Log.e(TAG, errorMsg);
        decryptor = null;
    }
}
\\...
\\ decrypting data
private void decryptData( byte[] encryptedData ) {
    if ( decryptor == null && encryptedData == null ) {
        Log.w(TAG, "Trying to decrypt with 'null' MDecryptor or empty decrypted string.");
        return;
    }
    try {
        String decrypted = decryptor.decrypt(encryptedData);
        Log.i(TAG, String.format("Decrypted:%n\t%s", decrypted));
    } catch (DecryptorException e) {
        Log.e(TAG, String.format("Error while trying to decrypt data." +
            "%n\t %s %n\t %s", e.getMessage(), e.getCause()));
    }
}
```

## TODO
- [ ] Publish a working sample.
- [x] Explain how to use the library.
- [x] Provide link to download from jCenter.
- [x] Automatically check the size of the encryption data, using `encryptLarge` only when necessary.
- [ ] Use random property while generating the Key.
- [ ] Give the possibility to customize the algorithm, provider and transformation.

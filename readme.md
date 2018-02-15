# MCipher Library
###### A Simple Encryption and Decryption Library for Android

- Compatible with from **SDK 19**
- Recommended to **SDK 23+**.
- VERSION 0.1

## Encrypting data
1. Instantiate and Initialize a `MEncryptor.class`.
2. Choose a unique identifier to be used as your Secret Key alias.
3. Call `MEncryptor.encrypt( String alias, String dataToEncrypt, Context context )`.
4. You can convert the received `byte[]` to a `String` using the utility method `MCipherUtils.encodeToStr(byte[] data)`.
5. When running **MCipher on Android version previous to 23**, it is **vital** to call `MEncryptor.encryptLargeData()` when trying to encrypt data with more than 200 symbols.

```java
MEncryptor encryptor;
final String keyAlias = "my.package.cipher.alias";
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
            encryptedData = encryptor.encrypt( keyAlias, dataToEncrypt, App.getContext() );
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
2. Call `MDecryptor.decrypt( String alias, final byte[] encryptedData )`.
3. Use the **alias** used during the encryption of the data.
4. When running **MCipher on Android version previous to 23**, it is **vital** to call `MDecryptor.decryptLargeData()` when trying to decrypt data with more than 200 symbols. **Notice that the data must have been encrypted with `MEncryptor.encryptLargeData()`.

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
        String decrypted = decryptor.decrypt(keyAlias, encryptedData);
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
- [ ] Provide link to download from jCenter.
- [ ] Automatically check the size of the encryption data, using `encryptLarge` only when necessary.
- [ ] Use random property while generating the Key.
- [ ] Give the possibility to customize the algorithm, provider and transformation.

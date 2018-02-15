package com.tinmegali.security.mcipher;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * A wrapper object used during encryption and decryption
 * process made by the {@link Encryptor} and {@link Decryptor} classes.
 *
 * The object is serialized during encryption and it may contains
 * the cipher's vector IV, if the encryption was done using the 'AES'
 * algorithm.
 */

class EncryptedObject implements Serializable {

    private final byte[] data;
    private byte[] cypherIV;


    private EncryptedObject(byte[] data) {
        this.data = data;
    }

    private EncryptedObject(byte[] data, byte[] cypherIV) {
        this( data );
        this.cypherIV = cypherIV;
    }

    public byte[] getData() {
        return data;
    }

    public byte[] getCypherIV() {
        return cypherIV;
    }

    static byte[] serializeEncryptedObj(byte[] encryptedData)
            throws IOException {
        EncryptedObject obj = new EncryptedObject(encryptedData);
        try (
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                ObjectOutputStream objOut = new ObjectOutputStream(out)
        ) {
            objOut.writeObject(obj);
            return out.toByteArray();
        }
    }

    // Append Cipher's IV with the Encrypted Data
    // using a EncryptedData object
    static byte[] serializeEncryptedObj(byte[] encryptedData, byte[] cypherIV)
            throws IOException
    {
        EncryptedObject data = new EncryptedObject(encryptedData, cypherIV);
        try (
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                ObjectOutputStream objOut = new ObjectOutputStream(out)
        ) {

            objOut.writeObject(data);
            return out.toByteArray();
        }
    }

    // retrieve EncryptedData object from byte[] array
    static EncryptedObject getEncryptedObject(byte[] data)
            throws IOException, ClassNotFoundException
    {
        try (
                ByteArrayInputStream in = new ByteArrayInputStream(data);
                ObjectInputStream objIn = new ObjectInputStream(in)
        ) {
            return (EncryptedObject) objIn.readObject();
        }
    }
}

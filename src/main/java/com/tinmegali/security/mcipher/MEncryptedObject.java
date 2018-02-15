package com.tinmegali.security.mcipher;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * A wrapper object used during encryption and decryption
 * process made by the {@link MEncryptor} and {@link MDecryptor} classes.
 *
 * The object is serialized during encryption and it may contains
 * the cipher's vector IV, if the encryption was done using the 'AES'
 * algorithm.
 */

class MEncryptedObject implements Serializable {

    private final byte[] data;
    private byte[] cypherIV;


    private MEncryptedObject(byte[] data) {
        this.data = data;
    }

    private MEncryptedObject(byte[] data, byte[] cypherIV) {
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
        MEncryptedObject obj = new MEncryptedObject(encryptedData);
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
        MEncryptedObject data = new MEncryptedObject(encryptedData, cypherIV);
        try (
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                ObjectOutputStream objOut = new ObjectOutputStream(out)
        ) {

            objOut.writeObject(data);
            return out.toByteArray();
        }
    }

    // retrieve EncryptedData object from byte[] array
    static MEncryptedObject getEncryptedObject(byte[] data)
            throws IOException, ClassNotFoundException
    {
        try (
                ByteArrayInputStream in = new ByteArrayInputStream(data);
                ObjectInputStream objIn = new ObjectInputStream(in)
        ) {
            return (MEncryptedObject) objIn.readObject();
        }
    }
}

package com.krestfield.ezsign.utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import com.krestfield.ezsign.KEzSignException;
import com.krestfield.ezsign.msg.KBase64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

/**
 * KEncrypt
 *
 * Copyright Krestfield 2016
  */
public class KEncrypt
{
    int LEN_SALT = 8;
    int LEN_IV = 16;
    int AES_KEY_LEN = 256;

    String m_password;

    /**
     * Constructor
     *
     * @param password
     * @throws KEzSignException
     */
    public KEncrypt(String password) throws KEzSignException
    {
        m_password = password;

        if (m_password == null || m_password.length() == 0)
            throw new KEzSignException("Unable to encrypt data as no password to encrypt with has been specified");
    }

    /**
     * Encrypts the supplied data with the password passed to the constructor
     * Returns a base64 string containing the encrypted data
     * @param data
     * @return
     */
    public String encryptData(String data) throws KEzSignException
    {
        byte[] encData = encryptData(m_password, data.getBytes());
        return KBase64.ToBase64String(encData);
    }

    /**
     * Decrypts the supplied data with the password passed to the constructor
     * Returns the clear text string
     * @param b64Data
     * @return
     */
    public String decryptData(String b64Data) throws KEzSignException
    {
        byte[] encData = KBase64.FromBase64String(b64Data);
        byte[] clearData = decryptData(m_password, encData);

        if (clearData == null)
            return null;
        else
            return new String(clearData);
    }

    /**
     * A utility method which generates a number of random bytes.  Used in IV and salt generation.
     * @param numBytes
     * @return
     */
    private byte[] generateRandomBytes(int numBytes)
    {
        SecureRandom r = new SecureRandom();
        byte[] rnd = new byte[numBytes];
        r.nextBytes(rnd);

        return rnd;
    }

    /**
     * Extracts the salt data from a file.  The format is:
     * Bytes Len  Data
     * 0-7   8    Salt
     * 8-15  16   IV
     * 16->  n    Encrypted data
     * The 8 salt bytes are returned.
     * @param originalData
     * @return
     */
    private byte[] extractSalt(byte[] originalData)
    {
        byte[] salt = new byte[LEN_SALT];
        for (int i = 0; i < LEN_SALT; i++)
        {
            salt[i] = originalData[i];
        }

        return salt;
    }

    /**
     * Extracts the IV data from a file.  The format is:
     * Bytes Len  Data
     * 0-7   8    Salt
     * 8-15  16   IV
     * 16->  n    Encrypted data
     * The 16 IV bytes are returned.
     * @param originalData
     * @return
     */
    private byte[] extractIV(byte[] originalData)
    {
        byte[] iv = new byte[16];
        int ivIndex = 0;
        for (int i = 8; i < 24; i++)
        {
            iv[ivIndex] = originalData[i];
            ivIndex++;
        }

        return iv;
    }


    /**
     * Generates an AES key based on the Password (which is a static variable) and the salt provided
     * @param salt
     * @return
     */
    private SecretKey generateKey(String password, byte[] salt) throws KEzSignException
    {
        try
        {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            char[] passwordChars = password.toCharArray();
            KeySpec spec = new PBEKeySpec(passwordChars, salt, 1024, AES_KEY_LEN);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

            return secret;
        }
        catch (Exception e)
        {
            throw new KEzSignException("There was an error generating the key from the password.  " + e.getMessage());
        }
    }

    /**
     * Encrypts a block of data.  Generates a new random salt and generates the key from this and the Password
     * already set.  Generates a new IV and encrypts the data.
     * The data returned is of the following format:
     * Bytes Len  Data
     * 0-7   8    Salt
     * 8-15  16   IV
     * 16->  n    Encrypted data
     * @param data
     * @return
     */
    private byte[] encryptData(String password, byte[] data) throws KEzSignException
    {
        byte[] salt = generateRandomBytes(LEN_SALT);
        byte[] iv = generateRandomBytes(LEN_IV);

        SecretKey sk = generateKey(password, salt);
        if (sk == null)
            return null;

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sk, new IvParameterSpec(iv));

            byte[] encData = cipher.doFinal(data);

            byte[] newData = new byte[encData.length + LEN_IV + LEN_SALT];
            System.arraycopy(salt, 0, newData, 0, LEN_SALT);
            System.arraycopy(iv, 0, newData, LEN_SALT, LEN_IV);
            System.arraycopy(encData, 0, newData, LEN_SALT + LEN_IV, encData.length);

            return newData;
        }
        catch (java.security.InvalidKeyException ke)
        {
            throw new KEzSignException("There was an error encrypting the data.  Check that the Java Cryptography " +
                    "Extensions for your Java environment have been installed.  " + ke.getMessage());
        }
        catch (Exception e)
        {
            throw new KEzSignException("There was an error encrypting the data.  " + e.getMessage());
        }
    }

    /**
     * Decrypts a block of data.  Extracts the salt from the data and generates the key from this and the Password
     * already set.  Extracts the IV and decrypts the data.
     * The data processed is in the following format:
     * Bytes Len  Data
     * 0-7   8    Salt
     * 8-15  16   IV
     * 16->  n    Encrypted data     * @param data
     * The clear data is returned.
     * @return
     */
    private byte[] decryptData(String password, byte[] data) throws KEzSignException
    {
        byte[] salt = extractSalt(data);
        byte[] iv = extractIV(data);

        byte[] cleanedData = new byte[data.length - (LEN_SALT + LEN_IV)];
        System.arraycopy(data, LEN_SALT + LEN_IV, cleanedData, 0, cleanedData.length);

        SecretKey sk = generateKey(password, salt);
        if (sk == null)
            return null;

        try
        {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(iv));

            return cipher.doFinal(cleanedData);
        }
        catch (java.security.InvalidKeyException ke)
        {
            throw new KEzSignException("There was an error decrypting the data.  Check that the Java Cryptography " +
                    "Extensions for your Java environment have been installed.  " + ke.getMessage());
        }
        catch (Exception e)
        {
            throw new KEzSignException("There was an error decrypting the data.  Check the password is correct.  Error: " + e.getMessage());
        }
    }
}
/********************************************************************************************************************/
/** END OF FILE *****************************************************************************************************/
/********************************************************************************************************************/
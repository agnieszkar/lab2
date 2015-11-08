package com;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.spec.AlgorithmParameterSpec;

public class Main {
    private static final int BLOCK_SIZE = 16;
    private static final byte[] IV = new byte[BLOCK_SIZE];

    public static void main(String[] args) {
        String schematSzyfrowania = args[1].toUpperCase();
        String trybSzyfrowania = args[2].toUpperCase();
        //String keystorePath = "resources/cryptographyKeystore.keystore";
        //String alias = "lab2_128";
        String keyStorePath = args[3];
        String alias = args[4];
        String filePath = args[5];
        try {
            InputStream fis = new FileInputStream();
            FileInputStream is = new FileInputStream(keyStorePath);
            KeyStore keystore = KeyStore.getInstance("jceks");
            char[] password = readPassword();
            keystore.load(is, password);
            Key key = keystore.getKey(alias, password);
            Cipher cipher = Cipher.getInstance(String.format("%s/%s/PKCS5Padding", schematSzyfrowania, trybSzyfrowania), "SunJCE");
            AlgorithmParameterSpec ivSpec = new IvParameterSpec(IV);
            switch(args[0]){
                case "decrypt":
                    encrypt(Cipher.DECRYPT_MODE, cipher,key,ivSpec);
                    break;
                case "encrypt":
                    encrypt(Cipher.ENCRYPT_MODE, cipher,key,ivSpec);
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static char[] readPassword() {
        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance");
            System.exit(0);
        }
        return console.readPassword("Enter password for keystore: ");
    }

    private static void encrypt(int mode, Cipher cipher, Key key, AlgorithmParameterSpec ivSpec, InputStream input) throws InvalidAlgorithmParameterException, InvalidKeyException, IOException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(mode, key, ivSpec);
        OutputStream fos = new FileOutputStream("resources/encryptionResult.txt");

        byte[] buffer = new byte[BLOCK_SIZE];
        int noBytes = 0;
        byte[] cipherBlock = new byte[cipher.getOutputSize(buffer.length)];
        int cipherBytes;
        while ((noBytes = input.read(buffer)) != -1) {
            cipherBytes = cipher.update(buffer, 0, noBytes, cipherBlock);
            fos.write(cipherBlock, 0, cipherBytes);
        }
        cipherBytes = cipher.doFinal(cipherBlock, 0);
        fos.write(cipherBlock, 0, cipherBytes);
        fos.close();
        input.close();
    }

    private static void decrypt(Cipher cipher, Key key, AlgorithmParameterSpec ivSpec) throws InvalidAlgorithmParameterException, InvalidKeyException, IOException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        InputStream fis = new FileInputStream("src/resources/encryptionResult.txt");
        OutputStream fos = new FileOutputStream("src/resources/decryptionResult.txt");

        byte[] buffer = new byte[BLOCK_SIZE];
        int noBytes = 0;
        byte[] cipherBlock = new byte[cipher.getOutputSize(buffer.length)];
        int cipherBytes;
        while ((noBytes = fis.read(buffer)) != -1) {
            cipherBytes = cipher.update(buffer, 0, noBytes, cipherBlock);
            fos.write(cipherBlock, 0, cipherBytes);
        }
        cipherBytes = cipher.doFinal(cipherBlock, 0);
        fos.write(cipherBlock, 0, cipherBytes);
        fos.close();
        fis.close();
    }
}

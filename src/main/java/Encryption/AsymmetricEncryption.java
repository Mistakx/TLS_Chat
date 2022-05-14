package Encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;

public class AsymmetricEncryption extends Encryption {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private String encryptionAlgorithmName;
    private int encryptionKeySize;

    /**
     * Divides an array of bytes into blocks of the same size
     *
     * @param source
     * @param chunkSize
     * @return
     */
    private static byte[][] divideArray(byte[] source, int chunkSize) {


        byte[][] ret = new byte[(int) Math.ceil(source.length / (double) chunkSize)][chunkSize];

        int start = 0;

        for (int i = 0; i < ret.length; i++) {
            ret[i] = Arrays.copyOfRange(source, start, start + chunkSize);
            start += chunkSize;
        }

        return ret;
    }

    /**
     * Constructor
     *
     * @param encryptionAlgorithmName Encryption Algorithm
     * @param encryptionKeySize Key size
     */
    public AsymmetricEncryption(String encryptionAlgorithmName, int encryptionKeySize) {
        try {
            this.encryptionAlgorithmName = encryptionAlgorithmName;
            this.encryptionKeySize = encryptionKeySize;
            generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
        }
    }

    @Override
    public String getAlgorithmName() {
        return encryptionAlgorithmName;
    }

    @Override
    public int getAlgorithmKeySize() {
        return encryptionKeySize;
    }

    /**
     * Generates the private and public key
     *
     * @throws NoSuchAlgorithmException
     */
    private void generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(encryptionAlgorithmName);
        keyPairGenerator.initialize(encryptionKeySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    /**
     * Encrypts the message with the chosen algorithm and key size
     *
     * @param message message to be encrypted
     * @param publicKey key to be used in the encryption
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     */
    public byte[] encryptMessage(byte[] message, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        Cipher cipher = Cipher.getInstance(encryptionAlgorithmName);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        int blockSize = encryptionKeySize / 8 - 11;
        byte[][] messageChunks = divideArray(message, blockSize);
        ByteArrayOutputStream encryptedMessage = new ByteArrayOutputStream();
        for (byte[] currentChunk : messageChunks) {
            encryptedMessage.write(cipher.doFinal(currentChunk));
        }
        return encryptedMessage.toByteArray();
    }

    /**
     * Decrypts the message with the chosen algorithm and key size
     *
     * @param message message to be decrypted
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     */
    public byte[] decryptMessage(byte[] message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        Cipher cipher = Cipher.getInstance(encryptionAlgorithmName);
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        int blockSize = encryptionKeySize / 8;
        byte[][] messageChunks = divideArray(message, blockSize);
        ByteArrayOutputStream decryptedMessage = new ByteArrayOutputStream();
        for (byte[] currentChunk : messageChunks) {
            decryptedMessage.write(cipher.doFinal(currentChunk));
        }
        return decryptedMessage.toByteArray();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }


}
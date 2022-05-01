package Encryption;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class SymmetricEncryption extends Encryption {

    private String encryptionAlgorithmName;
    private int encryptionKeySize;
    private SecretKey secretKey;


    private static byte[][] divideArray(byte[] source, int chunkSize) {
        byte[][] ret = new byte[(int) Math.ceil(source.length / (double) chunkSize)][chunkSize];
        int start = 0;
        for (int i = 0; i < ret.length; i++) {
            ret[i] = Arrays.copyOfRange(source, start, start + chunkSize);
            start += chunkSize;
        }
        return ret;
    }

    public SymmetricEncryption(String encAlg, int keySize) {
        this.encryptionAlgorithmName = encAlg;
        this.encryptionKeySize = keySize;
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
     * This function takes the message and the secret key to convert the message into CipherText.
     *
     * @param message the message to be encrypted
     * @param key     the secret key used
     * @return
     * @throws Exception
     */
    public byte[] do_SymEncryption(byte[] message, byte[] key) throws Exception {
        byte[] bytes = ByteBuffer.allocate(16).put(key).array();
        SecretKeySpec secretKey = new SecretKeySpec(bytes, encryptionAlgorithmName);
        Cipher cipher = Cipher.getInstance(encryptionAlgorithmName);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        int blockSize = cipher.getBlockSize(); // Block size is in bytes
        byte[][] messageChunks = divideArray(message, blockSize);
        ByteArrayOutputStream encryptedMessage = new ByteArrayOutputStream();
        for (byte[] currentChunk : messageChunks) {
            try {
                encryptedMessage.write(cipher.doFinal(currentChunk));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return encryptedMessage.toByteArray();
    }

    // This function performs the reverse operation of the do_SymEncryption function. It converts ciphertext to the plaintext using the key.

    /**
     * This function performs the reverse operation of the do_SymEncryption function. It converts the Encrypted text into the decrypted message using the key.
     *
     * @param message the message to be decrypted
     * @param key     the secret key used
     * @return
     * @throws Exception
     */
    public byte[] do_SymDecryption(byte[] message, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        byte[] bytes = ByteBuffer.allocate(16).put(key).array();
        SecretKeySpec secretKey = new SecretKeySpec(bytes, encryptionAlgorithmName);
        Cipher cipher = Cipher.getInstance(encryptionAlgorithmName);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        int blockSize = cipher.getBlockSize() * 8; // Block size is in bytes, so *8 to get bits
        byte[][] messageChunks = divideArray(message, blockSize);
        ByteArrayOutputStream decryptedMessage = new ByteArrayOutputStream();
        try {
            for (byte[] currentChunk : messageChunks) {
                decryptedMessage.write(cipher.doFinal(currentChunk));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptedMessage.toByteArray();
    }
}





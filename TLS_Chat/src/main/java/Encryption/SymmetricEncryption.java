package Encryption;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class SymmetricEncryption extends Encryption {

    private String encryptionAlgorithmName;
    private int encryptionKeySize;


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
        SecretKeySpec secretKey = new SecretKeySpec(key, encryptionAlgorithmName);
        Cipher cipher = Cipher.getInstance(encryptionAlgorithmName);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        int blockSize = cipher.getBlockSize(); // Block size is in bytes
        byte[][] messageChunks = divideArray(message, blockSize);
        ByteArrayOutputStream encryptedMessage = new ByteArrayOutputStream();
        for (byte[] currentChunk : messageChunks) {
            encryptedMessage.write(cipher.update(currentChunk));
        }
        return encryptedMessage.toByteArray();
    }

    /**
     * This function performs the reverse operation of the do_SymEncryption function. It converts the Encrypted text into the decrypted message using the key.
     *
     * @param message the message to be decrypted
     * @param key     the secret key used
     * @return
     * @throws Exception
     */
    public byte[] do_SymDecryption(byte[] message, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        SecretKeySpec secretKey = new SecretKeySpec(key, encryptionAlgorithmName);
        Cipher cipher = Cipher.getInstance(encryptionAlgorithmName);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        int blockSize = cipher.getBlockSize(); // Block size is in bytes, so *8 to get bits
        byte[][] messageChunks = divideArray(message, blockSize);
        ByteArrayOutputStream decryptedMessageOutputStream = new ByteArrayOutputStream();

        for (int i = 0; i < messageChunks.length; i++) {
            decryptedMessageOutputStream.write(cipher.update(messageChunks[i]));
        }

        byte[] appendedChunk = new byte[16]; // Used because the last update isn't working

        decryptedMessageOutputStream.write(cipher.update(appendedChunk));
        byte[] decryptedMessageBytes = decryptedMessageOutputStream.toByteArray();
        return decryptedMessageBytes;
    }
}





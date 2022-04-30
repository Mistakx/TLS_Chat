package Encryption;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class SymmetricEncryption extends Encryption{

    private String    encryptionAlgorithmName;
    private int       encryptionKeySize;
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

    public SymmetricEncryption ( String encAlg, int keySize ) {
        this.encryptionAlgorithmName = encAlg;
        this.encryptionKeySize = keySize;
    }

    @Override
    public String getAlgorithmName( ) {
        return encryptionAlgorithmName;
    }

    @Override
    public int getAlgorithmKeySize( ) {
        return encryptionKeySize;
    }


    /**
     * This function takes the message and the secret key to convert the message into CipherText.
     * @param message the message to be encrypted
     * @param key the secret key used
     * @return
     * @throws Exception
     */
    public byte[] do_SymEncryption( byte[] message, byte[] key ) throws Exception {
        byte[] bytes = ByteBuffer.allocate( 16 ).put( key ).array( );
        SecretKeySpec secretKey = new SecretKeySpec( bytes , encryptionAlgorithmName );
        Cipher cipher = Cipher.getInstance( encryptionAlgorithmName );
        cipher.init( Cipher.ENCRYPT_MODE, secretKey);

        cipher.getBlockSize();

        int blockSize = encryptionKeySize / 8 - 11;
        byte[][] messageChunks = divideArray(message, blockSize);
        ByteArrayOutputStream encryptedMessage = new ByteArrayOutputStream();
        for (byte[] currentChunk : messageChunks) {
            encryptedMessage.write(cipher.doFinal(currentChunk));
        }
        return encryptedMessage.toByteArray();
    }

    // This function performs the reverse operation of the do_SymEncryption function. It converts ciphertext to the plaintext using the key.
    /**
     * This function performs the reverse operation of the do_SymEncryption function. It converts the Encrypted text into the decrypted message using the key.
     * @param message the message to be decrypted
     * @param key the secret key used
     * @return
     * @throws Exception
     */
    public byte[] do_SymDecryption( byte[ ] message, byte[] key) throws Exception {
        byte[] bytes = ByteBuffer.allocate( 16 ).put( key ).array( );
        SecretKeySpec secretKey = new SecretKeySpec( bytes , encryptionAlgorithmName);
        Cipher cipher = Cipher.getInstance( encryptionAlgorithmName );
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        int blockSize = encryptionKeySize / 8;
        byte[][] messageChunks = divideArray(message, blockSize);
        ByteArrayOutputStream decryptedMessage = new ByteArrayOutputStream();
        for (byte[] currentChunk : messageChunks) {
            decryptedMessage.write(cipher.doFinal(currentChunk));
        }
        return decryptedMessage.toByteArray();
    }
}





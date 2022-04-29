package Encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class AsymmetricEncryption extends Encryption {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    private String encryptionAlgorithmName;
    private int encryptionKeySize;

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

    private void generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(encryptionAlgorithmName);
        keyPairGenerator.initialize(encryptionKeySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public byte[] encryptMessage(byte[] message, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(encryptionAlgorithmName);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message);
    }

    public byte[] decryptMessage(byte[] message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(encryptionAlgorithmName);
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        return cipher.doFinal(message);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }


}
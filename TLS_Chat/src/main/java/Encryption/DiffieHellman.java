package Encryption;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.Arrays;

public class DiffieHellman {

    //    private static final BigInteger G = BigInteger.valueOf(3);
//    private static final BigInteger N = BigInteger.valueOf(1289971646);

    private KeyPairGenerator keyPairGenerator;
    private KeyPair keyPair;

    public DiffieHellman() {

    }

    /**
     * Generates the private key
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public PrivateKey generatePrivateKey() throws NoSuchAlgorithmException {
//        Random randomGenerator = SecureRandom.getInstance( "SHA1PRNG" );
//        return new BigInteger( NUM_BITS , randomGenerator );

        keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        keyPair = keyPairGenerator.generateKeyPair();
        return keyPair.getPrivate();

    }

    /**
     * Generates the public key
     *
     * @return
     */
    public PublicKey generatePublicKey() {
//        return G.modPow( privateKey , N );
        PublicKey publickey = keyPair.getPublic();
        return publickey;
    }

    /**
     * Computes the private key
     *
     * @param publicKey publicKey
     * @param NUM_BITS Number of bits of the key
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public byte[] computePrivateKey(PublicKey publicKey, int NUM_BITS) throws NoSuchAlgorithmException, InvalidKeyException {
//        return publicKey.modPow(privateKey, N);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(publicKey, true);
        byte[] sharedsecret = keyAgreement.generateSecret();
        byte[] sharedSecretWithCorrectSize = Arrays.copyOfRange(sharedsecret,0, NUM_BITS/8);
        return sharedSecretWithCorrectSize;
    }


}


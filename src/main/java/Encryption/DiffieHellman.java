package Encryption;

import javax.crypto.KeyAgreement;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;
import java.util.Random;

public class DiffieHellman {

    //    private static final BigInteger G = BigInteger.valueOf(3);
//    private static final BigInteger N = BigInteger.valueOf(1289971646);

    private KeyPairGenerator keyPairGenerator;
    private KeyPair keyPair;

    public DiffieHellman() {

    }


    public PrivateKey generatePrivateKey() throws NoSuchAlgorithmException {
//        Random randomGenerator = SecureRandom.getInstance( "SHA1PRNG" );
//        return new BigInteger( NUM_BITS , randomGenerator );

        keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        keyPair = keyPairGenerator.generateKeyPair();
        return keyPair.getPrivate();

    }

    public PublicKey generatePublicKey() {
//        return G.modPow( privateKey , N );
        PublicKey publickey = keyPair.getPublic();
        return publickey;
    }

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


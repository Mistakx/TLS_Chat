package Encryption;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public abstract class DiffieHellman extends Encryption{

    private static final BigInteger G = BigInteger.valueOf( 3 );
    private static final BigInteger N = BigInteger.valueOf( 1289971646 );


    public static BigInteger generatePrivateKey (int NUM_BITS) throws NoSuchAlgorithmException {
        Random randomGenerator = SecureRandom.getInstance( "SHA1PRNG" );
        return new BigInteger( NUM_BITS , randomGenerator );
    }

    public static BigInteger generatePublicKey ( BigInteger privateKey ) {
        return G.modPow( privateKey , N );
    }

    public static BigInteger computePrivateKey ( BigInteger publicKey , BigInteger privateKey ) {
        return publicKey.modPow( privateKey , N );
    }
}


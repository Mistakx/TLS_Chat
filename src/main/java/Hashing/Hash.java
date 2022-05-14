package Hashing;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hash extends Hashing {

    private String hashAlgorithmName;
    private int blockSize;

    public Hash(String hashAlg, int bSize) {
        this.hashAlgorithmName = hashAlg;
        this.blockSize = bSize;
    }

    @Override
    public String getAlgorithmName() {
        return hashAlgorithmName;
    }

    @Override
    public int getBlockSize() {
        return blockSize;
    }


    public String applyHash(String message)
    {
        try {
            MessageDigest md = MessageDigest.getInstance(hashAlgorithmName);
            byte[] messageDigest = md.digest(message.getBytes());
            BigInteger no = new BigInteger(1, messageDigest);
            String hashtext = no.toString(16);
            while (hashtext.length() < blockSize) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}

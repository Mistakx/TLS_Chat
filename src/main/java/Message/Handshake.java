package Message;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

public record Handshake(
        String username,
        String encryptionAlgorithmType,
        String encryptionAlgorithmName,
        int encryptionKeySize,
        PublicKey publicKey,
        BigInteger privateSharedKey
) implements Serializable {
}

package Message;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

public record Handshake(
        String username,
        String encryptionAlgorithmType,
        String encryptionAlgorithmName,
        Integer encryptionKeySize,
        PublicKey asymmetricPublicKey,
        BigInteger diffieHellmanPublicKey

) implements Serializable {
}

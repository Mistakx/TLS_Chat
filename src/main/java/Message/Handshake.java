package Message;

import java.io.Serializable;
import java.security.PublicKey;

public record Handshake(
        String username,
        String encryptionAlgorithmType,
        String encryptionAlgorithmName,
        Integer encryptionKeySize,
        PublicKey publicKey

) implements Serializable {
}

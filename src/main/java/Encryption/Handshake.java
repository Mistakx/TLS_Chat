package Encryption;

import java.io.Serializable;
import java.security.PublicKey;

public record Handshake (
        String userName,
        String encryptionAlgorithmType,
        String encryptionAlgorithmName,
        int encryptionKeySize,
        PublicKey publicKey
) implements Serializable {
}

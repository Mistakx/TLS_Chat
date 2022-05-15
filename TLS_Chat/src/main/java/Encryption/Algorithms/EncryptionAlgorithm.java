package Encryption.Algorithms;

import java.util.List;

public abstract class EncryptionAlgorithm {

    public abstract String getType();
    public abstract String getName();
    public abstract List<Integer> getKeySizes();
}

package Encryption.Algorithms;

import java.util.List;

public class AES extends EncryptionAlgorithm {

    @Override
    public String getType() {
        return "Symmetric";
    }

    @Override
    public String getName() {
        return "AES";
    }

    @Override
    public List<Integer> getKeySizes() {
        List<Integer> keySizes = List.of(128, 192, 256);
        return keySizes;
    }

}

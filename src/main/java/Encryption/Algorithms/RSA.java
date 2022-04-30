package Encryption.Algorithms;

import java.util.List;

public class RSA extends EncryptionAlgorithm {

    @Override
    public String getType() {
        return "Asymmetric";
    }

    @Override
    public String getName() {
        return "RSA";
    }

    @Override
    public List<Integer> getKeySizes() {
        List<Integer> keySizes = List.of(512, 1024, 2048);
        return keySizes;
    }

}

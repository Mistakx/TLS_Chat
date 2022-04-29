package Encryption.Algorithms;

import java.util.List;

public class DES3 extends EncryptionAlgorithm {

    @Override
    public String getType() {
        return "Symmetric";
    }

    @Override
    public String getName() {
        return "DES";
    }

    @Override
    public List<Integer> getKeySizes() {
        List<Integer> keySizes = List.of(112, 168);
        return keySizes;
    }

}

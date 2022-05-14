package Hashing.Algorithms;

import java.util.List;

public class SHA256 extends HashingAlgorithm{

    @Override
    public String getName() {
        return "SHA-256";
    }

    @Override
    public List<Integer> getBlockSize() {
        List<Integer> keySizes = List.of(64);
        return keySizes;
    }
}

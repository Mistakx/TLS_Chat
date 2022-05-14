package Hashing.Algorithms;

import java.util.List;

public class SHA512 extends HashingAlgorithm{

    @Override
    public String getName() {
        return "SHA-512";
    }

    @Override
    public List<Integer> getBlockSize() {
        List<Integer> keySizes = List.of(32);
        return keySizes;
    }
}

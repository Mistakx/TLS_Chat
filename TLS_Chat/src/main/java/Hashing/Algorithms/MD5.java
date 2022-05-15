package Hashing.Algorithms;

import java.util.List;

public class MD5 extends HashingAlgorithm{

    @Override
    public String getName() {
        return "MD5";
    }

    @Override
    public List<Integer> getBlockSize() {
        List<Integer> keySizes = List.of(32);
        return keySizes;
    }
}

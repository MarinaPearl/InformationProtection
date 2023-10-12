package ru.demchuk.lab2;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;

public class SimonCipher {
    private static final long MASK = 0xFFFFFFFFFFFFFFFFL;
    private static final int[] Z = {0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0};
    private static final int[] SIGMA = {0xB, 0xE, 0xE, 0x9};

    private long[] key;
    private int rounds;

    public SimonCipher(BigInteger key, int rounds) {
        this.key = expandKey(key, rounds);
        this.rounds = rounds;
    }

    private long[] expandKey(BigInteger key, int rounds) {
        long[] keyWords = new long[rounds];
        long mask = 0xFFFFFFFFFFFFFFFFL;

        for (int i = 0; i < rounds; i++) {
            keyWords[i] = key.shiftRight((rounds - 1 - i) * 64).and(BigInteger.valueOf(mask)).longValue();
        }

        return keyWords;
    }

    private long leftRotate(long value, int shift, int size) {
        return ((value << shift) | (value >>> (size - shift))) & MASK;
    }

    private long rightRotate(long value, int shift, int size) {
        return ((value >>> shift) | (value << (size - shift))) & MASK;
    }

    private long[] roundFunction(long[] input, long roundKey) {
        long[] output = new long[2];
        output[0] = (leftRotate(input[0], 2, 64) & leftRotate(input[0], 13, 64)) ^ leftRotate(input[0], 22, 64);
        output[0] = output[0] ^ input[1] ^ roundKey;
        output[1] = leftRotate(input[1], 1, 64) ^ leftRotate(input[1], 10, 64) ^ leftRotate(input[1], 31, 64);

        return output;
    }

    public byte[] encrypt(byte[] plaintext) {
        int blockSize = 16; // 128 bits
        long[] block = new long[2];
        long[] ciphertext = new long[2];

        System.out.println("Encryption:");

        for (int i = 0; i < plaintext.length - 16; i += blockSize) {
            block[0] = ((plaintext[i] & 0xFFL) << 56) | ((plaintext[i + 1] & 0xFFL) << 48) | ((plaintext[i + 2] & 0xFFL) << 40) | ((plaintext[i + 3] & 0xFFL) << 32)
                    | ((plaintext[i + 4] & 0xFFL) << 24) | ((plaintext[i + 5] & 0xFFL) << 16) | ((plaintext[i + 6] & 0xFFL) << 8) | (plaintext[i + 7] & 0xFFL);
            block[1] = ((plaintext[i + 8] & 0xFFL) << 56) | ((plaintext[i + 9] & 0xFFL) << 48) | ((plaintext[i + 10] & 0xFFL) << 40) | ((plaintext[i + 11] & 0xFFL) << 32)
                    | ((plaintext[i + 12] & 0xFFL) << 24) | ((plaintext[i + 13] & 0xFFL) << 16) | ((plaintext[i + 14] & 0xFFL) << 8) | (plaintext[i + 15] & 0xFFL);

            System.out.println("Block " + (i / blockSize + 1) + " before encryption: " + blockToString(block));

            for (int round = 0; round < rounds; round++) {
                long[] tempBlock = block.clone();
                block[0] = block[1];
                block[1] = tempBlock[0] ^ roundFunction(tempBlock, key[round])[0];
            }

            ciphertext[0] = block[0];
            ciphertext[1] = block[1];

            System.out.println("Block " + (i / blockSize + 1) + " after encryption: " + blockToString(ciphertext));
            System.out.println();
        }

        return plaintext;
    }

    public byte[] decrypt(byte[] ciphertext) {
        int blockSize = 16; // 128 bits
        long[] block = new long[2];
        long[] plaintext = new long[2];

        System.out.println("Decryption:");

        for (int i = 0; i < ciphertext.length - 16; i += blockSize) {
            block[0] = ((ciphertext[i] & 0xFFL) << 56) | ((ciphertext[i + 1] & 0xFFL) << 48) | ((ciphertext[i + 2] & 0xFFL) << 40) | ((ciphertext[i + 3] & 0xFFL) << 32)
                    | ((ciphertext[i + 4] & 0xFFL) << 24) | ((ciphertext[i + 5] & 0xFFL) << 16) | ((ciphertext[i + 6] & 0xFFL) << 8) | (ciphertext[i + 7] & 0xFFL);
            block[1] = ((ciphertext[i + 8] & 0xFFL) << 56) | ((ciphertext[i + 9] & 0xFFL) << 48) | ((ciphertext[i + 10] & 0xFFL) << 40) | ((ciphertext[i + 11] & 0xFFL) << 32)
                    | ((ciphertext[i + 12] & 0xFFL) << 24) | ((ciphertext[i + 13] & 0xFFL) << 16) | ((ciphertext[i + 14] & 0xFFL) << 8) | (ciphertext[i + 15] & 0xFFL);

            System.out.println("Block " + (i / blockSize + 1) + " before decryption: " + blockToString(block));

            for (int round = rounds - 1; round >= 0; round--) {
                long[] tempBlock = block.clone();
                block[1] = block[0];
                block[0] = tempBlock[1] ^ roundFunction(tempBlock, key[round])[0];
            }

            plaintext[0] = block[0];
            plaintext[1] = block[1];

            System.out.println("Block " + (i / blockSize + 1) + " after decryption: " + blockToString(plaintext));
            System.out.println();
        }

        return ciphertext;
    }

    private String blockToString(long[] block) {
        return String.format("%016X %016X", block[0], block[1]);
    }

    public static void main(String[] args) {
        try {
            File file = new File("file.txt");
            FileInputStream fileInputStream = new FileInputStream(file);

            byte[] fileContent = new byte[(int) file.length()];
            fileInputStream.read(fileContent);

            fileInputStream.close();

            BigInteger key = new BigInteger("00112233445566778899AABBCCDDEEFF", 16);
            int rounds = 32;

            SimonCipher simon = new SimonCipher(key, rounds);

            // Пример использования для шифрования
            System.out.println("Plaintext: " + new String(fileContent));
            byte[] ciphertext = simon.encrypt(fileContent);
            System.out.println("Ciphertext: " + new String(ciphertext));

            // Пример использования для дешифрования
            byte[] decryptedText = simon.decrypt(ciphertext);
            System.out.println("Decrypted text: " + new String(decryptedText));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
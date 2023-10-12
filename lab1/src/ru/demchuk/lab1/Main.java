package ru.demchuk.lab1;

import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        Scanner in = new Scanner(System.in);
        String newString = in.nextLine();
        VernamCipher vernamCipher = new VernamCipher();
        String key = vernamCipher.generateKey(newString.length());
        String wordCipher = vernamCipher.encrypt(newString, key);
        System.out.println("encrypted: " + wordCipher);
        String dexWordCipher = vernamCipher.decrypt(wordCipher, key);
        System.out.println(dexWordCipher);
    }
}

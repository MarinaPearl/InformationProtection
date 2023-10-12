package ru.demchuk.lab1;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class VernamCipher {
    private final static String NAME = "Vernam Cipher";
    private final static char[] encryptionArr = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
    public VernamCipher(){

    }

    public String generateKey(int length){
        if(length <= 0){
            return null;
        }
        StringBuilder key = new StringBuilder();
        SecureRandom secureRandom = new SecureRandom();
        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        for(int i = 0; i < length; i++){
            int randomValue = secureRandom.nextInt(26);
            key.append(encryptionArr[randomValue]);
        }
        return key.toString();
    }

    public String encrypt(String plainText, String key){
        if(plainText.length() != key.length()){
            return null;
        }
        byte[] plainTextBytes = plainText.getBytes();
        byte[] keyBytes = key.getBytes();
        byte[] encryptedText = new byte[plainTextBytes.length];
        for(int i = 0; i < plainTextBytes.length; i++){
            encryptedText[i] = (byte) (keyBytes[i] ^ plainTextBytes[i]);
        }
        return new String(encryptedText);
    }

    public String decrypt(String cipherText, String key){
        if(cipherText.length() != key.length()){
            return null;
        }
        byte[] cipherTextBytes = cipherText.getBytes();
        byte[] keyBytes = key.getBytes();
        byte[] decryptedText = new byte[cipherTextBytes.length];
        for(int i = 0; i < cipherTextBytes.length; i++){
            decryptedText[i] = (byte) (keyBytes[i] ^ cipherTextBytes[i]);
        }
        return new String(decryptedText).toUpperCase();
    }
}

import java.util.*;
import java.lang.*;
import java.io.*;

public class AvalancheEffectTester {

    public static void main(String[] args) {
        testAvalancheEffect();
    }

    public static void testAvalancheEffect() {
        // Инициализация входных данных и ключа
//        "Original Input"
//        "Modified Input"

        // Запоминаем зашифрованные данные для оригинальных входных данных
        byte[] originalEncrypted = encryption("TEST1").getBytes();

        // Запоминаем зашифрованные данные для модифицированных входных данных
        byte[] modifiedEncrypted = encryption("TEST2").getBytes();

        // Измеряем процент изменения
        double percentageDifference = calculatePercentageDifference(originalEncrypted, modifiedEncrypted);

        // Выводим результат
        System.out.println("Percentage Difference: " + percentageDifference + "%");
    }

    private static double calculatePercentageDifference(byte[] arr1, byte[] arr2) {
        int differences = 0;
        int totalBits = arr1.length * 8;

        for (int i = 0; i < arr1.length; i++) {
            differences += Integer.bitCount(arr1[i] ^ arr2[i]);
        }

        return (differences / (double) totalBits) * 100;
    }

    private static String encryption(String fileName) {
        FastReader scan = new FastReader(System.in);
        ArrayList<String> pt = new ArrayList<>();
        ArrayList<String> ct = new ArrayList<>();
        int t = 1;

        while (t-- > 0) {
            SimonCipher sk = new SimonCipher();

            final byte[] key64 = {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b};
            final byte[] key128 = {0X00, 0X01, 0X02, 0X03, 0X04, 0X05, 0X06, 0X07, 0X08, 0X09, 0X0A, 0X0B, 0X0C, 0X0D, 0X0E, 0X0F};
            File f = new File(fileName);


            // Encryption
            readFile(f, pt);
            for (String s : pt) {
                sk.initialize(s.getBytes(), 128, key128, 0);
                ct.add(Base64.getEncoder().encodeToString(sk.encrypt()));
            }
        }

        StringBuilder result = new StringBuilder();
        for (String s : ct) {
            result.append(s);
        }
        return result.toString();
    }

    private static void readFile(File f, ArrayList<String> s) {
        try {
            BufferedReader br = new BufferedReader(new FileReader(f));
            String read = "";
            while ((read = br.readLine()) != null) {
                s.add(read);
            }
            br.close();
        } catch (Exception e) {
            //Won't happen
        }
    }

    static class FastReader {
        InputStream in;
        FastReader(InputStream is) {
            in = is;
        }
    }
}

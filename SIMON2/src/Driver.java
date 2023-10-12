import java.util.*;
import java.lang.*;
import java.io.*;

public class Driver {
    static PrintWriter out=new PrintWriter(new OutputStreamWriter(System.out));
    public static void main(String[] Args)throws Exception{
        FastReader scan=new FastReader(System.in);
        int t=1;
//        t=scan.nextInt();
        while(t-->0){
            SimonCipher sk=new SimonCipher();

            final byte[] key64 = {0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b,0x10,0x11,0x12,0x13,0x18,0x19,0x1a,0x1b};
//            final byte[] io64 = {0X2D,0X43,0X75,0X74,0X74,0X65,0X72,0X3B};
            final byte[] key128 =  {0X00, 0X01, 0X02, 0X03, 0X04, 0X05, 0X06, 0X07, 0X08, 0X09, 0X0A, 0X0B, 0X0C, 0X0D, 0X0E, 0X0F};
//            final byte[] io128 = {0X20, 0X6D, 0X61, 0X64, 0X65, 0X20, 0X69, 0X74, 0X20, 0X65, 0X71, 0X75, 0X69, 0X76, 0X61, 0X6C};
            File f = new File("TEST");
            ArrayList<String> pt=new ArrayList<>();
            ArrayList<String> ct=new ArrayList<>();


         // Encryption
            readFile(f,pt);
            for(String s:pt){
                sk.initialize(s.getBytes(),128,key128,0);
                ct.add(Base64.getEncoder().encodeToString(sk.encrypt()));
            }
            writeFile(f,ct);


//          Decryption
//            readFile(f,ct);
//            for(String s:ct){
//                sk.initialize(Base64.getDecoder().decode(s),128,key128,1);
//                pt.add(new String(sk.decrypt()));
//            }
//            writeFile(f,pt);
        }
        out.flush();
        out.close();
    }
    private static void readFile(File f,ArrayList<String> s){
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
    private static void writeFile(File f,ArrayList<String> s){
        try {
            BufferedWriter bw = new BufferedWriter(new FileWriter(f,false));
            for(String ss:s){
                bw.write(ss);
                bw.newLine();
            }
            bw.flush();
            bw.close();
        } catch (Exception e) {
            //Won't happen
        }
    }
    private static void printBytes(final byte[] data) {
        for (int i = 0; i < data.length; i++) {
            System.out.printf("%02X ", data[i]);
        }
        System.out.println();
    }
    static class FastReader {

        byte[] buf = new byte[2048];
        int index, total;
        InputStream in;

        FastReader(InputStream is) {
            in = is;
        }

        int scan() throws IOException {
            if (index >= total) {
                index = 0;
                total = in.read(buf);
                if (total <= 0) {
                    return -1;
                }
            }
            return buf[index++];
        }

        String next() throws IOException {
            int c;
            for (c = scan(); c <= 32; c = scan()) ;
            StringBuilder sb = new StringBuilder();
            for (; c > 32; c = scan()) {
                sb.append((char) c);
            }
            return sb.toString();
        }

        int nextInt() throws IOException {
            int c, val = 0;
            for (c = scan(); c <= 32; c = scan()) ;
            boolean neg = c == '-';
            if (c == '-' || c == '+') {
                c = scan();
            }
            for (; c >= '0' && c <= '9'; c = scan()) {
                val = (val << 3) + (val << 1) + (c & 15);
            }
            return neg ? -val : val;
        }
        long nextLong() throws IOException {
            int c;
            long val = 0;
            for (c = scan(); c <= 32; c = scan()) ;
            boolean neg = c == '-';
            if (c == '-' || c == '+') {
                c = scan();
            }
            for (; c >= '0' && c <= '9'; c = scan()) {
                val = (val << 3) + (val << 1) + (c & 15);
            }
            return neg ? -val : val;
        }
    }
}

//This class contains various methods common between the ciphers
class Utilities {

    static class PKCS5Padding {
        private int xtra;
        private int size;

        //block size in bytes
        void initialize(int size) {
            this.size = size;
        }

        //adds the padding to the input array
        byte[] addPKCS5Padding(byte[] arr) {
            xtra = size - arr.length % size;
            byte[] ret = new byte[arr.length + xtra];
            for (int i = 0; i < arr.length; i++) {
                ret[i] = arr[i];
            }
            byte add=(byte)xtra;
            int a=add;
            for (int i = 0; i < xtra; i++) {
                ret[arr.length + i] = (byte) xtra;
            }
            return ret;
        }

        //removes the num padded bytes from the given array
        byte[] removePKCS5Padding(byte[] arr) {
            int v=arr[arr.length-1];
            byte[] ret = new byte[arr.length - v];
            for (int i = 0; i < arr.length - v; i++) {
                ret[i] = arr[i];
            }
            return ret;
        }
    }

    //Convert the required number of bytes into a long/usable form
    //takes in input byte array, starting index, the size of the word in bytes
    //returns a long value which will be used for the cipher rounds
    public static long bytesToLong(byte[] in, int from,int size) {
        long ret=0;
        int i=0;
        while(i<size){
            ret=(ret<<8)|(in[from++]&0xffL);
            i++;
        }
        return ret;
    }

    //takes input as the encrypted word, the output byte array
    //size of the word in bytes, the end index for the bytes
    //sets the bytes of the output array accordingly
    public static void longToBytes(long val,byte[] out,int size, int till){
        int i=0;
        while(i<size){
            out[till--]=(byte)(val);
            val>>=8;
            i++;
        }
    }

    public static long rotateRight(long num,int s,int size){
        return (num>>>s)|(num<<(size-s));
    }

    public static long rotateLeft(long num,int s,int size){
        return (num<<s)|(num>>>(size-s));
    }
}




import java.util.Arrays;

class SimonCipher{
    Utilities.PKCS5Padding pad;
    private final byte[][] z;
    private int sizeBits;
    private int sizeBytes;
    private byte[] input;
    private byte[] encryted;
    private byte[] keyInitial;
    private int keyWords;
    private int zi=0;
    private int r=0;
    private long[] keys;
    private long c;
    private long mask;
    SimonCipher() {
        pad=new Utilities.PKCS5Padding();
        z = new byte[][] {
                {01, 01, 01, 01, 01, 00, 01, 00, 00, 00, 01, 00, 00, 01, 00, 01, 00, 01, 01, 00, 00, 00, 00, 01, 01, 01, 00, 00, 01, 01, 00, 01, 01, 01, 01, 01, 00, 01, 00, 00, 00, 01, 00, 00, 01, 00, 01, 00, 01, 01, 00, 00, 00, 00, 01, 01, 01, 00, 00, 01, 01, 00, },
                {01, 00, 00, 00, 01, 01, 01, 00, 01, 01, 01, 01, 01, 00, 00, 01, 00, 00, 01, 01, 00, 00, 00, 00, 01, 00, 01, 01, 00, 01, 00, 01, 00, 00, 00, 01, 01, 01, 00, 01, 01, 01, 01, 01, 00, 00, 01, 00, 00, 01, 01, 00, 00, 00, 00, 01, 00, 01, 01, 00, 01, 00, },
                {01, 00, 01, 00, 01, 01, 01, 01, 00, 01, 01, 01, 00, 00, 00, 00, 00, 00, 01, 01, 00, 01, 00, 00, 01, 00, 00, 01, 01, 00, 00, 00, 01, 00, 01, 00, 00, 00, 00, 01, 00, 00, 00, 01, 01, 01, 01, 01, 01, 00, 00, 01, 00, 01, 01, 00, 01, 01, 00, 00, 01, 01, },
                {01, 01, 00, 01, 01, 00, 01, 01, 01, 00, 01, 00, 01, 01, 00, 00, 00, 01, 01, 00, 00, 01, 00, 01, 01, 01, 01, 00, 00, 00, 00, 00, 00, 01, 00, 00, 01, 00, 00, 00, 01, 00, 01, 00, 00, 01, 01, 01, 00, 00, 01, 01, 00, 01, 00, 00, 00, 00, 01, 01, 01, 01, },
                {01, 01, 00, 01, 00, 00, 00, 01, 01, 01, 01, 00, 00, 01, 01, 00, 01, 00, 01, 01, 00, 01, 01, 00, 00, 00, 01, 00, 00, 00, 00, 00, 00, 01, 00, 01, 01, 01, 00, 00, 00, 00, 01, 01, 00, 00, 01, 00, 01, 00, 00, 01, 00, 00, 01, 01, 01, 00, 01, 01, 01, 01, }
        };
    }
    void initialize(byte[] input,int blockSize,byte[] key,int mode)throws IllegalArgumentException{
        this.sizeBits=blockSize;
        sizeBytes=sizeBits/8;
        pad.initialize(sizeBytes);
        keyInitial=key;
        keyWords=(key.length*2)/sizeBytes;
        boolean flag=((key.length*2)%sizeBytes==0);
        switch (sizeBits){
            case 32:
                mask=0x000000000000FFFFL;
                if(keyWords!=4||!flag){
                    throw new IllegalArgumentException();
                }else{
                    r=32;
                    zi=-2;
                }
                break;
            case 48:
                mask=0x0000000000FFFFFFL;
                if(flag) {
                    if (keyWords == 3) {
                        r = 36;
                        zi = -1;
                    } else if (keyWords == 4) {
                        r = 36;
                        zi = -1;
                    } else {
                        throw new IllegalArgumentException();
                    }
                }else{
                    throw new IllegalArgumentException();
                }
                break;
            case 64:
                mask=0x00000000FFFFFFFFL;
                if(flag) {
                    if (keyWords == 3) {
                        r = 42;
                        zi = 1;
                    } else if (keyWords == 4) {
                        r = 44;
                        zi = 1;
                    } else {
                        throw new IllegalArgumentException();
                    }
                }else{
                    throw new IllegalArgumentException();
                }
                break;
            case 96:
                mask=0x0000FFFFFFFFFFFFL;
                if(flag) {
                    if (keyWords == 2) {
                        r = 52;
                        zi = 2;
                    } else if (keyWords == 3) {
                        r = 54;
                        zi = 2;
                    } else {
                        throw new IllegalArgumentException();
                    }
                }else{
                    throw new IllegalArgumentException();
                }
                break;
            case 128:
                mask=0xFFFFFFFFFFFFFFFFL;
                if(flag) {
                    if (keyWords == 2) {
                        r = 68;
                        zi = 2;
                    } else if (keyWords == 3) {
                        r = 69;
                        zi = 2;
                    } else if(keyWords==4){
                        r=72;
                        zi=2;
                    } else {
                        throw new IllegalArgumentException();
                    }
                }else{
                    throw new IllegalArgumentException();
                }
                break;
            default:
                throw new IllegalArgumentException();
        }
        zi=zi+keyWords-2;
        if(mode==0) {
            this.input = pad.addPKCS5Padding(input);
        }else{
            this.input=input;
        }
        c=mask-3;
        makeKeys();
//        System.out.println(Arrays.toString(keys));
    }
    private void makeKeys(){
        keys=new long[r];
        for(int i=0;i<keyWords;i++){
            keys[i]=Utilities.bytesToLong(keyInitial,(keyWords-i-1)*sizeBytes/2,sizeBytes/2);
        }
        for(int i=keyWords;i<r;i++){
            long temp=Utilities.rotateRight(keys[i-1],3,sizeBits/2);
            temp=temp&mask;
            if(keyWords==4){
                temp^=keys[i-3];
            }
            temp=temp^Utilities.rotateRight(temp,1,sizeBits/2);
            keys[i]=temp^keys[i-keyWords]^z[zi][(i-keyWords)%62]^c;
        }
    }
    byte[] encrypt(){
        byte[] out=new byte[input.length];
        int l=input.length/sizeBytes;
        for(int i=0;i<l;i++){
            long x=Utilities.bytesToLong(input,2*i*sizeBytes/2,sizeBytes/2);
            long y=Utilities.bytesToLong(input,(2*i+1)*sizeBytes/2,sizeBytes/2);
//            System.out.println(x+" "+y);
            for(int j=0;j<r;j++){
                long temp=x;
                x=(y^((Utilities.rotateLeft(x,1,sizeBits/2)&Utilities.rotateLeft(x,8,sizeBits/2))^Utilities.rotateLeft(x,2,sizeBits/2)^keys[j]));
                x=x&mask;
                y=temp;
            }
//            System.out.println(x+" "+y);
            Utilities.longToBytes(x,out,sizeBytes/2,(2*i+1)*sizeBytes/2-1);
            Utilities.longToBytes(y,out,sizeBytes/2,(2*i+2)*sizeBytes/2-1);
        }
        input=out;
//        printBytes(encryted);
//        return out;
//        return pad.removePKCS5Padding(out);
        return out;
    }
    byte[] decrypt(){
//        byte[] input=encryted;
        byte[] out=new byte[input.length];
        int l=input.length/sizeBytes;
        for(int i=0;i<l;i++){
            long x=Utilities.bytesToLong(input,2*i*sizeBytes/2,sizeBytes/2);
            long y=Utilities.bytesToLong(input,(2*i+1)*sizeBytes/2,sizeBytes/2);
            for(int j=r-1;j>=0;j--){
                long temp=y;
                y=(x^((Utilities.rotateLeft(y,1,sizeBits/2)&Utilities.rotateLeft(y,8,sizeBits/2))^Utilities.rotateLeft(y,2,sizeBits/2)^keys[j]));
                y=y&mask;
                x=temp;
            }
            Utilities.longToBytes(x,out,sizeBytes/2,(2*i+1)*sizeBytes/2-1);
            Utilities.longToBytes(y,out,sizeBytes/2,(2*i+2)*sizeBytes/2-1);
        }
//        return out;
        return pad.removePKCS5Padding(out);
    }
    private static void printBytes(final byte[] data) {
        for (int i = 0; i < data.length; i++) {
            System.out.printf("%02X ", data[i]);
        }
        System.out.println();
    }
}

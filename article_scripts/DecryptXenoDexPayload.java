import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.InflaterInputStream;
import java.util.zip.InflaterOutputStream;

/**
Decrypt encrypted dex payload in sample SHA256:259e88f593a3df5cf14924eec084d904877953c4a78ed4a2bc9660a2eaabb20b.
Found in resources/assets/sqvgk/lkfupve.gvo.

Usage:
javac DecryptXenoDexPayload.java
java DecryptXenoDexPayload <input file path> <output file path>
(The input file should be the encrypted dex file.)

@cano32
 */

public class DecryptXenoDexPayload {
    public static String sssjdgsvrgt = "捨뺑戚\ue684聳踖曡㒕躚\udafdﶃ킎";

    public static void main(String[] args) {
        System.out.println("----- Decrypt encrypted dex payload in sample sha256: 259e88f593a3df5cf14924eec084d904877953c4a78ed4a2bc9660a2eaabb20b -----");
        
        if (args.length > 0) {
            String input = args[0];
            String output = args[1];
            try {
                FileInputStream inputFile = new FileInputStream(input);
                FileOutputStream outputFile = new FileOutputStream(output);
                qepfhiwqjjpmg(inputFile, outputFile);
                System.out.println("Output file produced at " + output);
            } catch (Exception e) {
                System.out.println("Error: Failed to decrypt encrypted dex payload.\n\nUsage:\njavac DecryptXenoDexPayload.java\njava DecryptXenoDexPayload <input file path> <output file path>\n\nThe input file should be the encrypted dex file.\n-----");
                e.printStackTrace();
            }
        }
        else {
            System.out.println("Error: No command line arguments found.\n\nUsage:\njavac DecryptXenoDexPayload.java\njava DecryptXenoDexPayload <input file path> <output file path>\n\nThe input file should be the encrypted dex file.");
        }
    }

    public static void qepfhiwqjjpmg(InputStream input, OutputStream output) throws Exception {
        InflaterInputStream is = new InflaterInputStream(input);
        InflaterOutputStream os = new InflaterOutputStream(output);
        jgqf(is, os);
        os.close();
        is.close();
    }

    private static void jgqf(InputStream inputStream, OutputStream outputStream) throws Exception {
        char[] key = sssjdgsvrgt.toCharArray();
        int[] iArr = {key[0] | (key[1] << 16), (key[3] << 16) | key[2], (key[5] << 16) | key[4], (key[7] << 16) | key[6]};
        int[] iArr2 = {(key[9] << 16) | key[8], key[10] | (key[11] << 16)};
        int[] iArr3 = kkvicc(iArr);
        byte[] bArr = new byte[8192];

        int i32 = 0;
        while (true) {
            int read = inputStream.read(bArr);
            if (read < 0) {
                return;
            }
            int i42 = i32 + read;
            int i52 = 0;
            while (i32 < i42) {
                int i6 = i32 % 8;
                int i7 = i6 / 4;
                int i8 = i32 % 4;
                if (i6 == 0) {
                    sswg(iArr3, iArr2);
                }
                bArr[i52] = (byte) (((byte) (iArr2[i7] >> (i8 * 8))) ^ bArr[i52]);
                i32++;
                i52++;
            }
            outputStream.write(bArr, 0, read);
        }
    }

    private static int[] kkvicc(int[] iArr) {
        int[] iArr2 = new int[27];
        int i = iArr[0];
        iArr2[0] = i;
        int[] iArr3 = new int[3];
        iArr3[0] = iArr[1];
        iArr3[1] = iArr[2];
        iArr3[2] = iArr[3];
        for (int i2 = 0; i2 < 26; i2++) {
            iArr3[i2 % 3] = (((iArr3[i2 % 3] >>> 8) | (iArr3[i2 % 3] << 24)) + i) ^ i2;
            i = ((i << 3) | (i >>> 29)) ^ iArr3[i2 % 3];
            iArr2[i2 + 1] = i;
        }
        return iArr2;
    }

    private static void sswg(int[] iArr, int[] iArr2) {
        int i = iArr2[0];
        int i2 = iArr2[1];

        for (int j=0; j<=25; j++) {
            i2 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[j];
            i = ((i << 3) | (i >>> 29)) ^ i2;
        }

        int i228 = (((i2 >>> 8) | (i2 << 24)) + i) ^ iArr[26];
        iArr2[0] = ((i << 3) | (i >>> 29)) ^ i228;
        iArr2[1] = i228;
    }
}

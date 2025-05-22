import java.util.ArrayList;

/**
Decrypt encrypted C2 found in Telegram bio, in 2nd stage dex payload from sample SHA256:259e88f593a3df5cf14924eec084d904877953c4a78ed4a2bc9660a2eaabb20b.

Usage:
javac DecryptTelegramC2.java
java DecryptTelegramC2

@cano32
 */

public class DecryptTelegramC2 {

    public static void main(String[] args){
    	System.out.println("----- Decrypt Telegram Bio Strings -----");

        String str = "🖤🖤🖤Building Skirt Appear grw Hand Tea Degree 0 lwb Follow Similar Everything Fresh🖤🖤🖤";
        int i = 0;
        int i2 = 0;
        ArrayList arrayList = new ArrayList();

        // ExternalMnemonicResourceApiUrlSource
        while (i != -1) {
            i = str.indexOf("🖤🖤🖤", i + i2);
            // UtilGlobal.Log("ExternalTextResourceApiUrlSource", "FI:" + i);
            if (i != -1) {
                int indexOf = str.indexOf("🖤🖤🖤", "🖤🖤🖤".length() + i);
                // UtilGlobal.Log("ExternalTextResourceApiUrlSource", "CI:" + indexOf);
                if (indexOf != -1) {
                    String decrypt = decrypt(str.substring(i + "🖤🖤🖤".length(), indexOf));
                    System.out.println("Decrypted: " + decrypt);
                    // UtilGlobal.Log("ExternalTextResourceApiUrlSource", "Found URL:" + decrypt);
                    // if (!arrayList.contains(decrypt)) {
                    //     arrayList.add(decrypt);
                    //     this.urls.add(new StringApiUrl(decrypt));
                    // }
                    i = indexOf + "🖤🖤🖤".length();
                }
            }
            // i2 = this.begin.length();
        }
    }

    // ExternalMnemonicResourceApiUrlSource
    private static String decrypt(String str) {
        String[] split = str.split(" ");
        StringBuilder sb = new StringBuilder();
        int i = 0;
        for (String str2 : split) {
            if (parseIntOrNull(str2) != null) {
                sb.append(parseIntOrNull(str2));
            } else if (str2.length() == 3 && caeDecrypt(str2, i).equals("dot")) {
                sb.append(".");
            } else {
                sb.append(str2.charAt(i % str2.length()));
            }
            i++;
        }
        return sb.toString();
    }
        
        
    // UtilEncryption
    public static String caeDecrypt(String str, int i) {
        String lowerCase = str.toLowerCase();
        StringBuilder sb = new StringBuilder();
        for (int i2 = 0; i2 < lowerCase.length(); i2++) {
            char charAt = lowerCase.charAt(i2);
            String $2 = "abcdefghijklmnopqrstuvwxyz";
            int indexOf = ($2.indexOf(charAt) - i) % 26;
            if (indexOf < 0) {
                indexOf += 26;
            }
            sb.append($2.charAt(indexOf));
        }
        return sb.toString();
    }

    // UtilGlobal
    public static Integer parseIntOrNull(String str) {
        try {
            return Integer.valueOf(Integer.parseInt(str));
        } catch (NumberFormatException unused) {
            return null;
        }
    }
}


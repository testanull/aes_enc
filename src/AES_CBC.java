import java.io.*;

public class AES_CBC {
    public static boolean DEBUG = false;


    public static void main(String[] args) {
        long startTime = System.nanoTime();
        String option = args[0];
        String keyFile = args[1];
        String fileData = args[2];
        String iv = toHexString("TGF4SSF0Kqiw85Ee");
        String key = getKey(keyFile);
        key = toHexString(key);
        if (!validateInputLine(key)) {
            throw new IllegalArgumentException("Key is malformed");
        }
        DataCrypto aes = new DataCrypto(key);
        BufferedReader in = null;
        PrintWriter out = null;

        try {
            in = new BufferedReader(new FileReader(fileData));
            String line;
            if (option.equals("e")) {
                out = new PrintWriter(fileData + ".enc");
                line = in.readLine();
                String[] line_split = line.split("(?<=\\G.{16})");
                String current_xk = iv;
                for (int i = 0; i < line_split.length; i++) {
                    String line_sub = line_split[i];
                    line_sub = xor(line_sub, fromHexString(current_xk));
                    line_sub = toHexString(line_sub);
                    if (validateInputLine(line_sub)) {
                        String ret = aes.encrypt(line_sub);
                        System.out.println("Encrypted: " + ret);
                        current_xk = ret;
                        out.print(ret);
                    }

                }
            } else if (option.equals("d")) {
                out = new PrintWriter(fileData + ".dec");
                line = in.readLine();
                String[] line_split = line.split("(?<=\\G.{32})");
                String current_xk = iv;
                for (int i = 0; i < line_split.length; i++) {
                    String line_sub = line_split[i];
                    if (validateInputLine(line_sub)) {
                        String ret = aes.decrypt(line_sub);
                        ret = xor(fromHexString(ret), fromHexString(current_xk));
                        System.out.println("Decrypted: " + ret);
                        out.println(ret);
                    }
                    current_xk = line_sub;
                }

            }
            in.close();
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }


        long endTime = System.nanoTime();
        double timeRun = (endTime - startTime) / 1000000000.0;
        System.out.println("Time to run option " + option + " on " + fileData + " : " + timeRun);

    }

    private static void debug(String[] args) {
        AES_CBC.DEBUG = true;
        String option = args[1];
        String key = args[2];
        String data = args[3];
        if (!validateInputLine(key)) {
            throw new IllegalArgumentException("Key is malformed");
        }
        if (option.equals("e")) {
            DataCrypto aes = new DataCrypto(key);
            String ret = "";
            if (validateInputLine(data))
                ret = aes.encrypt(data);
            System.out.println();
            System.out.println("Key: \n" + key);
            System.out.println("Plaintext: \n" + data);
            System.out.println("Cipher: \n" + ret);
        } else if (option.equals("d")) {
            DataCrypto aes = new DataCrypto(key);
            String ret = "";
            if (validateInputLine(data))
                ret = aes.decrypt(data);
            System.out.println();
            System.out.println("Key: \n" + key);
            System.out.println("Cipher: \n" + data);
            System.out.println("Plaintext: \n" + ret);
        }
    }

    private static boolean validateInputLine(String key) {
        for (int i = 0; i < 256 && i < key.length(); ++i) {  // hard code 256
            char c = key.charAt(i);
            boolean t = ((c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F'));
            if (!t)
                return false;
        }
        return true;
    }

    private static String getKey(String keyFile) {
        String key = "";
        BufferedReader inKey = null;
        try {
            inKey = new BufferedReader(new FileReader(keyFile));
            key = inKey.readLine();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            throw new IllegalArgumentException("Can't find the key file");
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (inKey != null) {
                try {
                    inKey.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return key;
    }

    public static String toHexString(String input) {
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < input.length(); i++)
            str.append(String.format("%02X", (int)input.charAt(i)));
        return str.toString();
    }

    public static String fromHexString(String hex) {
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            str.append((char) Integer.parseInt(hex.substring(i, i + 2), 16));
        }
        return str.toString();
    }

    public static String xor(String plaintext, String key) {
        if (key.length() < 1)
            return plaintext;

        String ciphertext = "";

        for (int i = 0; i < plaintext.length(); i++) {
            char pc = plaintext.charAt(i);
            char cc = (char) (pc ^ key.charAt(i));
            ciphertext += cc;
        }

        return ciphertext;
    }

}


public class KeyExpansion {
    Word[] keyExp;

    public KeyExpansion(String key) {
        keyExp = new Word[DataCrypto.totalWords];
        for (int i = 0; i < keyExp.length; ++i)
            keyExp[i] = new Word();

        keyExpansion(key);
    }

    private void copyKey(String key) {
        int num = 0;
        boolean flag = true; // variable used to stop the loops
        for (int i = 0; i < DataCrypto.Nk && flag; ++i) {
            for (int j = 0; j < Constants.Nb && flag; ++j) {
                String twoChars = key.substring(num, num += 2);
                byte t = (byte) ((Character.digit(twoChars.charAt(0), 16) << 4)
                        + Character.digit(twoChars.charAt(1), 16));
                keyExp[i].add(t);

                // handle the case when the key string longer or shorter than expected.
                if (key.length() == num) {
                    flag = false;
                }
                if (key.length() == num + 1) {
                    key = key.concat("0");
                }
            }
        }
    }

    private Word subWord(Word d) {
        Word temp = new Word();
        for (int i = 0; i < d.length(); ++i) {
            byte t = d.get(i);
            char c = Constants.S[(t < 0) ? (t + 256) : t];
            temp.add((byte) c);
        }
        return temp;
    }

    private Word rotWord(Word d) {
        return d.cyclicP();
    }

    private Word getRcon(int i) {
        byte value = (byte) Constants.Rcon[i];
        byte[] t = {value, 0, 0, 0};
        return new Word(t);
    }


    public void keyExpansion(String key) {
        copyKey(key);

        Word temp;
        for (int i = DataCrypto.Nk; i < DataCrypto.totalWords; ++i) {
            temp = keyExp[i-1];
            if (i % DataCrypto.Nk ==0) {
                temp = subWord(rotWord(temp)).xor(getRcon(i/ DataCrypto.Nk));
            }
            else if (DataCrypto.Nk > 6 && i % DataCrypto.Nk == 4) {
                temp = subWord(temp);
            }

            keyExp[i] = keyExp[i - DataCrypto.Nk].xor(temp);
        }
    }

    // used for debug
    // print key word by word
    public void printKey() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < DataCrypto.totalWords; ++i) {
            for (int j = 0; j < Constants.Nb; ++j) {
                byte t = keyExp[i].get(j);
                int tInt = (t < 0) ? (t + 256) : t;
                sb.append(Integer.toHexString(tInt >>> 4 & 0xF));
                sb.append(Integer.toHexString(t & 0xF));

            }
            sb.append(" ");
            if (i != 0 && (i + 1) % (DataCrypto.Nr + 1) == 0) {
                sb.append("\n");
            }
        }
        System.out.println(sb.toString().toUpperCase());
    }
}

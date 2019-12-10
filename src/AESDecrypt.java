
public class AESDecrypt extends AESCrypto{

    public AESDecrypt(byte[][] state, KeyExpansion key) {
        super(state, key);
    }

    private void invSubBytes() {
        for (int i = 0; i < state[0].length; ++i) {
            for (int j = 0; j < state.length; ++j) {
                byte t = state[j][i];
                char c = Constants.INV_S[(t < 0) ? (t + 256) : t];
                state[j][i] = (byte) c;
            }
        }
    }

    private void invShiftRows() {
        byte temp0;
        byte temp1;

        // row 2
        temp0 = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = temp0;

        // row 3
        temp0 = state[2][0];
        temp1 = state[2][1];
        state[2][0] = state[2][2];
        state[2][1] = state[2][3];
        state[2][2] = temp0;
        state[2][3] = temp1;

        // row 4
        temp0 = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = temp0;
    }

    public void mixColumn() {
        for (int i = 0; i < state[0].length; ++i) {
            invMixColumn2(i);
        }
    }

    public void decrypt() {
        addRoundKey(DataCrypto.Nr);
        for (int i = DataCrypto.Nr - 1; 0 < i ; --i) {
            invShiftRows();
            invSubBytes();
            addRoundKey(i);
            mixColumn();
        }
        invShiftRows();
        invSubBytes();
        addRoundKey(0);
    }


    public void invMixColumn2 (int c) {
        byte a[] = new byte[4];

        for (int i = 0; i < 4; i++)
            a[i] = state[i][c];

        state[0][c] = (byte)(mul(0xE,a[0]) ^ mul(0xB,a[1]) ^ mul(0xD, a[2]) ^ mul(0x9,a[3]));
        state[1][c] = (byte)(mul(0xE,a[1]) ^ mul(0xB,a[2]) ^ mul(0xD, a[3]) ^ mul(0x9,a[0]));
        state[2][c] = (byte)(mul(0xE,a[2]) ^ mul(0xB,a[3]) ^ mul(0xD, a[0]) ^ mul(0x9,a[1]));
        state[3][c] = (byte)(mul(0xE,a[3]) ^ mul(0xB,a[0]) ^ mul(0xD, a[1]) ^ mul(0x9,a[2]));
    }

    public void decryptDB() {

        addRoundKey(DataCrypto.Nr);
        System.out.println("After addRoundKey(" + DataCrypto.Nr + "):");
        printState();
        for (int i = DataCrypto.Nr - 1; 0 < i ; --i) {
            invShiftRows();
            System.out.println("After invShiftRows:");
            printState();
            invSubBytes();
            System.out.println("After invSubBytes:");
            printState();
            addRoundKey(i);
            System.out.println("After addRoundKey(" + i + "):");
            printState();
            mixColumn();
            System.out.println("After invMixColumn:");
            printState();
        }

        invShiftRows();
        System.out.println("After invShiftRows:");
        printState();
        invSubBytes();
        System.out.println("After invSubBytes:");
        printState();
        addRoundKey(0);
        System.out.println("After addRoundKey(" + 0+ "):");
        printState();

        keyObj.printKey();
    }

}

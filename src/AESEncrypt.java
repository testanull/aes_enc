
public class AESEncrypt extends AESCrypto{


    public AESEncrypt(byte[][] state, KeyExpansion key) {
        super(state, key);
    }

    public void encrypt() {
        addRoundKey(0);
        for (int i = 1; i < DataCrypto.Nr; ++i) {
            subBytes();
            shiftRows();
            mixColumn();
            addRoundKey(i);
        }

        subBytes();
        shiftRows();
        addRoundKey(DataCrypto.Nr);
    }

    private void subBytes() {
        for (int i = 0; i < state[0].length; ++i) {
            for (int j = 0; j < state.length; ++j) {
                byte t = state[j][i];
                char c = Constants.S[(t < 0) ? (t + 256) : t];
                state[j][i] = (byte) c;
            }
        }
    }

    private void shiftRows() {
        byte temp0;
        byte temp1;

        // row 2
        temp0 = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp0;

        // row 3
        temp0 = state[2][0];
        temp1 = state[2][1];
        state[2][0] = state[2][2];
        state[2][1] = state[2][3];
        state[2][2] = temp0;
        state[2][3] = temp1;

        // row 4
        temp0 = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = temp0;
    }

    public void mixColumn() {
        for (int i = 0; i < state[0].length; ++i) {
            mixColumn2(i);
        }
    }

    // --------- start professor code ----------------- //

    // In the following two methods, the input c is the column number in
    // your evolving state matrix st (which originally contained
    // the plaintext input but is being modified).  Notice that the state here is defined as an
    // array of bytes.  If your state is an array of integers, you'll have
    // to make adjustments.

    private void mixColumn2 (int c) {
        // This is another alternate version of mixColumn, using the
        // logtables to do the computation.

        byte a[] = new byte[4];

        // note that a is just a copy of st[.][c]
        for (int i = 0; i < 4; i++)
            a[i] = state[i][c];

        // This is exactly the same as mixColumns1, if
        // the mul columns somehow match the b columns there.
        state[0][c] = (byte)(mul(2,a[0]) ^ a[2] ^ a[3] ^ mul(3,a[1]));
        state[1][c] = (byte)(mul(2,a[1]) ^ a[3] ^ a[0] ^ mul(3,a[2]));
        state[2][c] = (byte)(mul(2,a[2]) ^ a[0] ^ a[1] ^ mul(3,a[3]));
        state[3][c] = (byte)(mul(2,a[3]) ^ a[1] ^ a[2] ^ mul(3,a[0]));
    } // mixColumn2

    // ------------- End of professor's code -------------------------- //



    // used for debug
    public void encryptDB() {

        addRoundKey(0);
        System.out.println("After addRoundKey(" + 0 + "):");
        printState();
        for (int i = 1; i < DataCrypto.Nr; ++i) {
            subBytes();
            System.out.println("After subBytes:");
            printState();
            shiftRows();
            System.out.println("After shiftRows:");
            printState();
            mixColumn();
            System.out.println("After mixColumn:");
            printState();
            addRoundKey(i);
            System.out.println("After addRoundKey(" + i + "):");
            printState();
        }

        subBytes();
        System.out.println("After subBytes:");
        printState();
        shiftRows();
        System.out.println("After shiftRows:");
        printState();
        addRoundKey(DataCrypto.Nr);
        System.out.println("After addRoundKey(" + DataCrypto.Nr + "):");
        printState();

        keyObj.printKey();
    }

}


public class AESCrypto {

    byte[][] state;
    KeyExpansion keyObj;

    AESCrypto(byte[][] state, KeyExpansion key) {
        this.state = state;
        keyObj = key;
    }

    public void addRoundKey(int round) {
        for (int i = 0; i < state[0].length; ++i) {
            for (int j = 0; j < state.length; ++j) {
                state[j][i] = (byte) (state[j][i] ^ keyObj.keyExp[round*Constants.Nb+i].get(j));
            }
        }
    }


    byte mul (int a, byte b) {
        int inda = (a < 0) ? (a + 256) : a;
        int indb = (b < 0) ? (b + 256) : b;

        if ( (a != 0) && (b != 0) ) {
            int index = (Constants.LogTable[inda] + Constants.LogTable[indb]);
            byte val = (byte)(Constants.AlogTable[ index % 255 ] );
            return val;
        }
        else
            return 0;
    } // mul


    String getState() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < state[0].length; ++i) {
            for (int j = 0; j < state.length; ++j) {
                byte t = state[j][i];
                int tInt = (t < 0) ? (t + 256) : t;
                sb.append(Integer.toHexString(tInt >>> 4 & 0xF));
                sb.append(Integer.toHexString(t & 0xF));
            }
        }
        return sb.toString().toUpperCase();
    }


    void printState() {
        System.out.println(getState());
    }
}

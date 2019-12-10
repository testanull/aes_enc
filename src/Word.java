
public class Word {
    private int count;
    byte[] data;

    public Word() {
        count = 0;
        data = new byte[Constants.Nb];
        for (int i = 0; i < data.length; ++i) {
            data[i] = 0;
        }

    }

    public Word(byte[] t) {
        data = new byte[Constants.Nb];
        count = 0;
        for (int i = 0; i < Constants.Nb; ++i) {
            data[i] = t[i];
        }
    }

    // copy constructor
    public Word(Word w) {
        data = new byte[Constants.Nb];
        count = 0;
        for (int i = 0; i < data.length; ++i) {
            data[i] = w.get(i);
        }
    }

    public void add(byte b) {
        data[count] = b;
        ++count;
        if (count == data.length) {
            count = 0;
        }
    }

    public int length() {
        return data.length;
    }

    public byte get(int i) {
        return data[i];
    }

    public void add (int index, byte value) {
        data[index] = value;
    }

    public Word cyclicP() {
        Word t = new Word();
        t.data[0] = data[1];
        t.data[1] = data[2];
        t.data[2] = data[3];
        t.data[3] = data[0];
        return t;
    }

    public Word xor(Word w) {
        Word temp = new Word();
        for (int i = 0; i < data.length; ++i) {
            temp.data[i] = (byte) (this.data[i] ^ w.data[i]);
        }

        return temp;
    }
}

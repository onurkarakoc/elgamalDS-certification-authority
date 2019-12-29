import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ElgamalDS {

    private BigInteger p;
    private BigInteger g;
    private BigInteger privateKey;

    public ElgamalDS(BigInteger p, BigInteger g){
        setP(p);
        setG(g);
    }

    public ElgamalDS(BigInteger p, BigInteger g, BigInteger privateKey){
        setP(p);
        setG(g);
        setPrivateKey(privateKey);
    }


    public BigInteger generatePublicKey(){
        FastModularExponentiation fastModularExponentiation = new FastModularExponentiation();
        return fastModularExponentiation.exponentMod(g,privateKey,p);
    }

    public BigInteger[] createS1AndS2(byte[] fileToByteArray) throws NoSuchAlgorithmException {
        FastModularExponentiation fastModularExponentiation = new FastModularExponentiation();
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(fileToByteArray);
        BigInteger m = new BigInteger(1, messageDigest.digest());
        BigInteger k = BigInteger.valueOf(13);
        BigInteger[] s1AndS2Array = new BigInteger[2];
        s1AndS2Array[0] = fastModularExponentiation.exponentMod(g, k, p);
        BigInteger inverseOfK = k.modInverse(p.subtract(BigInteger.ONE));
        BigInteger temp = m.subtract(s1AndS2Array[0].multiply(this.privateKey));
        s1AndS2Array[1] = inverseOfK.multiply(temp).mod(BigInteger.valueOf(22));
        return s1AndS2Array;
    }

    public boolean verifyMessage(BigInteger m, BigInteger s1, BigInteger s2, BigInteger publicKey){
        FastModularExponentiation fastModularExponentiation = new FastModularExponentiation();
        BigInteger v1 = fastModularExponentiation.exponentMod(g, m, p);
        BigInteger v2 = fastModularExponentiation.exponentMod(publicKey, s1, p);
        v2 = v2.multiply(fastModularExponentiation.exponentMod(s1, s2, p));
        v2 = v2.mod(p);
        if(v1.compareTo(v2) == 0) {
            return true;
        }
        return false;
    }



    //////////////////////////////////////////////////////////////////////

    public BigInteger getP() {
        return p;
    }

    public void setP(BigInteger p) {
        this.p = p;
    }

    public BigInteger getG() {
        return g;
    }

    public void setG(BigInteger g) {
        this.g = g;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }
}

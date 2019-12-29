import java.math.BigInteger;

public class DHKE {
    private BigInteger privateKey;
    public BigInteger p;
    public BigInteger g;

    public DHKE(BigInteger privateKey, BigInteger p, BigInteger g){
        setPrivateKey(privateKey);
        setP(p);
        setG(g);
    }

    public BigInteger generate(){
        FastModularExponentiation fastModularExponentiation = new FastModularExponentiation();
        return fastModularExponentiation.exponentMod(g, privateKey, p);
    }

    public BigInteger generateCommonKey(BigInteger publicKey, BigInteger comingPart){
        FastModularExponentiation fastModularExponentiation = new FastModularExponentiation();
        return fastModularExponentiation.exponentMod(comingPart, privateKey, p);
    }


    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

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
}

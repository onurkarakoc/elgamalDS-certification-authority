import java.math.BigInteger;

public class Certificate {

    private String certificationAName;
    private String subjectName;
    private BigInteger publicKey;
    private BigInteger p;
    private BigInteger g;
    private BigInteger s1;
    private BigInteger s2;

    public Certificate(String certificationAName, String subjectName, BigInteger publicKey, BigInteger p, BigInteger g){
        setCertificationAName(certificationAName);
        setSubjectName(subjectName);
        setPublicKey(publicKey);
        setP(p);
        setG(g);
    }

    public Certificate(String certificationAName, String subjectName, BigInteger publicKey, BigInteger p, BigInteger g, BigInteger s1, BigInteger s2){
        setCertificationAName(certificationAName);
        setSubjectName(subjectName);
        setPublicKey(publicKey);
        setP(p);
        setG(g);
        setS1(s1);
        setS2(s2);
    }

    public String getCertificationAName() {
        return certificationAName;
    }

    public void setCertificationAName(String certificationAName) {
        this.certificationAName = certificationAName;
    }

    public String getSubjectName() {
        return subjectName;
    }

    public void setSubjectName(String subjectName) {
        this.subjectName = subjectName;
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(BigInteger publicKey) {
        this.publicKey = publicKey;
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

    public BigInteger getS1() {
        return s1;
    }

    public void setS1(BigInteger s1) {
        this.s1 = s1;
    }

    public BigInteger getS2() {
        return s2;
    }

    public void setS2(BigInteger s2) {
        this.s2 = s2;
    }
}

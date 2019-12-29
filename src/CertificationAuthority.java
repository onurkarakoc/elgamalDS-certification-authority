import java.io.FileWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;

public class CertificationAuthority {

    public static BigInteger publicKey;
    private BigInteger privateKey;

    public CertificationAuthority(BigInteger privateKey){
        setPrivateKey(privateKey);
    }

    public void generatePublicKey(){
        ElgamalDS elgamalDS = new ElgamalDS(BigInteger.valueOf(23), BigInteger.valueOf(2), privateKey);
        setPublicKey(elgamalDS.generatePublicKey());
    }

    public void createCertificate(BigInteger publicKey, String name){
        Certificate certificate = new Certificate("Certification Authority", name, publicKey,BigInteger.valueOf(23), BigInteger.valueOf(2));
        try{
            FileWriter fileWriter = new FileWriter("Certificate_" + name + ".txt");
            fileWriter.write(certificate.getCertificationAName() +"\n");
            fileWriter.write(certificate.getSubjectName()+"\n");
            fileWriter.write(certificate.getPublicKey().toString()+"\n");
            fileWriter.write(certificate.getP().toString()+"\n");
            fileWriter.write(certificate.getG().toString() + "\n");
            fileWriter.close();
        }catch (Exception e){System.out.println(e);}
    }

    public void signAndAppendCertificate(String name) throws NoSuchAlgorithmException {
        ElgamalDS elgamalDS = new ElgamalDS(BigInteger.valueOf(23), BigInteger.valueOf(2), privateKey);
        BigInteger[] resultS1S2 = elgamalDS.createS1AndS2(this.readCertificateAndConvertByteArray(name));
        try {
            FileWriter fileWriter = new FileWriter("Certificate_" + name + ".txt", true);
            fileWriter.append("!\n");
            fileWriter.append(resultS1S2[0].toString() + "\n");
            fileWriter.append(resultS1S2[1].toString());
            fileWriter.close();
        }catch (Exception e){System.out.println(e);}
    }

    public byte[] readCertificateAndConvertByteArray(String name){
        byte[] fileToByteArray = null;
        try{
            fileToByteArray = Files.readAllBytes(Paths.get("Certificate_" + name + ".txt"));
        }catch (Exception e){System.out.println(e);}
        return fileToByteArray;
    }

    public void sendCertificateToPerson(Person person){
        person.setComingCertificateBytes(readCertificateAndConvertByteArray(person.getName()));
    }



//////////////////////////////////////////////////////
    public BigInteger getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(BigInteger publicKey) {
        this.publicKey = publicKey;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        CertificationAuthority certificationAuthority = new CertificationAuthority(BigInteger.valueOf(7));
        FastModularExponentiation fastModularExponentiation = new FastModularExponentiation();
        certificationAuthority.generatePublicKey();
        System.out.println(certificationAuthority.getPublicKey());
        certificationAuthority.createCertificate(certificationAuthority.getPublicKey(), "Alice");
       // BigInteger[] s1s2 = certificationAuthority.createS1AndS2(certificationAuthority.readCertificateAndConvertByteArray("Alice"),BigInteger.valueOf(23), BigInteger.valueOf(2));
       // MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
       // messageDigest.update(certificationAuthority.readCertificateAndConvertByteArray("Alice"));
       // BigInteger m = new BigInteger(1, messageDigest.digest());
       // BigInteger v1 = fastModularExponentiation.exponentMod(BigInteger.valueOf(2),m , BigInteger.valueOf(23));
       // BigInteger v2 = certificationAuthority.getPublicKey().modPow(s1s2[0],BigInteger.valueOf(23)).multiply(s1s2[0].modPow(s1s2[1],BigInteger.valueOf(23))).mod(BigInteger.valueOf(23));
       // System.out.println(v1);
       // System.out.println(v2);

    }
}

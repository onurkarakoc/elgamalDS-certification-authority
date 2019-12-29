import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Person {

    private String name;
    public BigInteger publicKey;
    private BigInteger privateKey;
    private byte[] comingCertificateBytes;
    private Certificate certificate;
    private BigInteger comingPartOfDHKE;
    private BigInteger commonKey;
    private Certificate comingCertificate;
    private String message;

    public Person(BigInteger privateKey, String name){
        setPrivateKey(privateKey);
        setName(name);
    }

    public void generatePublicKey(){
        ElgamalDS elgamalDS = new ElgamalDS(BigInteger.valueOf(23), BigInteger.valueOf(2), privateKey);
        setPublicKey(elgamalDS.generatePublicKey());
    }

    public void comingCertificate(){
        try{
            FileOutputStream fileOutputStream = new FileOutputStream("MY_CERTIFICATE_" + name + ".txt");
            fileOutputStream.write(comingCertificateBytes);
            fileOutputStream.close();
        }catch (Exception e){System.out.println(e);}
    }

    public void convertTxtToCertificateObj(){
        try{
            File file = new File("MY_CERTIFICATE_" + name + ".txt");
            BufferedReader bufferedReader = new BufferedReader(new FileReader(file));
            String certificationAuthorityName = bufferedReader.readLine();
            String subjectName = bufferedReader.readLine();
            BigInteger certificatePublicKey = new BigInteger(bufferedReader.readLine());
            BigInteger p = new BigInteger(bufferedReader.readLine());
            BigInteger g = new BigInteger(bufferedReader.readLine());
            bufferedReader.readLine();
            BigInteger s1 = new BigInteger(bufferedReader.readLine());
            BigInteger s2 = new BigInteger(bufferedReader.readLine());
            setCertificate(new Certificate(certificationAuthorityName, subjectName, certificatePublicKey, p, g));
            this.getCertificate().setS1(s1);
            this.getCertificate().setS2(s2);
        }catch (Exception e ){System.out.println(e);}
    }

    public boolean verifyMessageOfCertificationAuthority() throws NoSuchAlgorithmException {
        ElgamalDS elgamalDS = new ElgamalDS(BigInteger.valueOf(23), BigInteger.valueOf(2));
        int counter = 0;
        for(int i=0; i<this.comingCertificateBytes.length; i++) {
            if ((char) comingCertificateBytes[i] == '!') {
                break;
            }
            counter+= 1;
        }
        byte[] message = new byte[counter] ;
        for(int i=0; i<this.comingCertificateBytes.length; i++){
            if((char) comingCertificateBytes[i] == '!'){
                break;
            }
            message[i] = comingCertificateBytes[i];
        }
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(message);
        BigInteger m = new BigInteger(1, messageDigest.digest());
        return elgamalDS.verifyMessage(m, this.getCertificate().getS1(), this.getCertificate().getS2(), CertificationAuthority.publicKey);
    }

    public BigInteger sendPartOfDHKE(){
        DHKE dhke = new DHKE(privateKey,BigInteger.valueOf(23), BigInteger.valueOf(2));
        return dhke.generate();
    }

    public BigInteger generateCommonKey(){
        DHKE dhke = new DHKE(privateKey, BigInteger.valueOf(23), BigInteger.valueOf(2));
        return dhke.generateCommonKey(privateKey, comingPartOfDHKE);
    }

    public Certificate sendCertificateWithSignature(Person person) throws NoSuchAlgorithmException {
        Certificate certificate;
        ElgamalDS elgamalDS = new ElgamalDS(BigInteger.valueOf(23), BigInteger.valueOf(2), privateKey);
        BigInteger[] resultS1S2 = elgamalDS.createS1AndS2(comingCertificateBytes);
        certificate = new Certificate(getCertificate().getCertificationAName(), name, publicKey, BigInteger.valueOf(23), BigInteger.valueOf(2), resultS1S2[0], resultS1S2[1]);
        person.setComingCertificateBytes(this.comingCertificateBytes);
        return certificate;
    }

    public boolean verifyMessage(BigInteger publicKey, Certificate certificate) throws NoSuchAlgorithmException {
        ElgamalDS elgamalDS = new ElgamalDS(BigInteger.valueOf(23), BigInteger.valueOf(2));
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(getComingCertificateBytes());
        BigInteger m = new BigInteger(1, messageDigest.digest());
        return elgamalDS.verifyMessage(m, certificate.getS1(), certificate.getS2(), publicKey);
    }

    public void acceptCertificate(BigInteger publicKey, Certificate certificate) throws NoSuchAlgorithmException {
        if(this.verifyMessage(publicKey, certificate)){
            System.out.println("Certificate is valid and accepted");
            setComingCertificate(certificate);
        }
        else{
            System.out.println("Certificate is invalid and not accepted");
            setComingCertificate(null);
        }
    }

    public void sendMessageAfterEncryption(Person person) throws Exception {
        ElgamalDS elgamalDS = new ElgamalDS(BigInteger.valueOf(23), BigInteger.valueOf(2), this.privateKey);
        String message = "Helloooooo";
        BigInteger[] s1AndS2 = elgamalDS.createS1AndS2(message.getBytes());
        message = message + "!" + s1AndS2[0].toString() + " " + s1AndS2[1].toString();
        AES aes = new AES();
        aes.setKey(commonKey.toString());
        person.setMessage(aes.encrypt(message, aes.getSecretKey()));
    }

    public void decryptAndValidateMessage(Person person) throws NoSuchAlgorithmException {
        ElgamalDS elgamalDS = new ElgamalDS(BigInteger.valueOf(23), BigInteger.valueOf(2));
        AES aes = new AES();
        aes.setKey(commonKey.toString());
        String message = aes.decrypt(this.getMessage());
        String[] messageAndSignature = message.split("!");
        String[] s1AndS2 = messageAndSignature[1].split(" ");
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(messageAndSignature[0].getBytes());
        if(elgamalDS.verifyMessage(new BigInteger(1, messageDigest.digest()), new BigInteger(s1AndS2[0]), new BigInteger(s1AndS2[1]),person.publicKey)){
            System.out.println("Message is verified sender is correct and message is: " + messageAndSignature[0]);
        }
        else{
            System.out.println("Message cannot be verified!!!!");
        }
    }






    ////////////////////////////////////////////////////////////////////////

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

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public byte[] getComingCertificateBytes() {
        return comingCertificateBytes;
    }

    public void setComingCertificateBytes(byte[] comingCertificateBytes) {
        this.comingCertificateBytes = comingCertificateBytes;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public BigInteger getComingPartOfDHKE() {
        return comingPartOfDHKE;
    }

    public void setComingPartOfDHKE(BigInteger comingPartOfDHKE) {
        this.comingPartOfDHKE = comingPartOfDHKE;
    }

    public BigInteger getCommonKey() {
        return commonKey;
    }

    public void setCommonKey(BigInteger commonKey) {
        this.commonKey = commonKey;
    }

    public Certificate getComingCertificate() {
        return comingCertificate;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public void setComingCertificate(Certificate comingCertificate){
        this.comingCertificate = comingCertificate;
    }

    public static void main(String[] args) throws Exception {
        Person alice = new Person(BigInteger.valueOf(5), "Alice");
        alice.generatePublicKey();
    }
}

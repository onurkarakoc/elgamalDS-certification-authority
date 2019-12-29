import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public class Main {

    public static void main(String[] args) throws Exception {
        CertificationAuthority certificationAuthority = new CertificationAuthority(BigInteger.valueOf(7));
        Person alice = new Person(BigInteger.valueOf(3), "Alice");
        Person bob = new Person(BigInteger.valueOf(5), "Bob");

        certificationAuthority.generatePublicKey();
        alice.generatePublicKey();
        bob.generatePublicKey();

        certificationAuthority.createCertificate(alice.getPublicKey(), "Alice");
        certificationAuthority.signAndAppendCertificate("Alice");
        certificationAuthority.sendCertificateToPerson(alice);

        alice.comingCertificate();
        alice.convertTxtToCertificateObj();
        alice.verifyMessageOfCertificationAuthority();
        /* ************** */
        certificationAuthority.createCertificate(bob.getPublicKey(), "Bob");
        certificationAuthority.signAndAppendCertificate("Bob");
        certificationAuthority.sendCertificateToPerson(bob);
        bob.comingCertificate();
        bob.convertTxtToCertificateObj();
        bob.verifyMessageOfCertificationAuthority();

        bob.setComingPartOfDHKE(alice.sendPartOfDHKE());
        alice.setComingPartOfDHKE(bob.sendPartOfDHKE());
        alice.setCommonKey(alice.generateCommonKey());
        bob.setCommonKey(bob.generateCommonKey());
        alice.getCommonKey();
        bob.getCommonKey();

        bob.acceptCertificate(alice.publicKey,alice.sendCertificateWithSignature(bob));

        alice.acceptCertificate(bob.publicKey, bob.sendCertificateWithSignature(alice));

        alice.sendMessageAfterEncryption(bob);
        bob.decryptAndValidateMessage(alice);







    }
}

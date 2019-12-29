import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class AES {
    //Initial Vector is for the cipher block chaining.
    private static SecretKeySpec secretKey;
    private static byte[] key;
    private static final String initVector = "encryptionIntVec";

    public void setKey(String myKey)
    {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public String encrypt(String data, SecretKey secretKey) throws Exception{
        try{
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector.getBytes("UTF-8"));
            //We have to keep the key in global so that we can decrypt.
            //AES is algorithm, CBC is cipher block chaining and PKCS5PADDING is block size mechanism.
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encodedValue = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encodedValue);
        }
        catch (Exception e){
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public String decrypt(String encrypted){
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector.getBytes("UTF-8"));
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, this.secretKey, ivParameterSpec);
            byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
            return new String(original);
        }
        catch (Exception e){
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    //We're generating a key randomly and key size is 256 bit.
    private SecretKey randomKeyGenerator() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey;

    }

    public static String getInitVector() {
        return initVector;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

}

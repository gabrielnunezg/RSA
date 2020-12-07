import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.Cipher;

public class RSA {
    public static void saveKeyToFile(String fileName, BigInteger modulus, BigInteger exponent) throws IOException
    {
        ObjectOutputStream ObjOutputStream = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));
        try
        {
            ObjOutputStream.writeObject(modulus);
            ObjOutputStream.writeObject(exponent);
        } catch (Exception e)
        {
            e.printStackTrace();
        } finally
        {
            ObjOutputStream.close();
        }
    }

    public static Key readKeyFromFile(String keyFileName) throws IOException {
        Key key = null;
        InputStream inputStream = new FileInputStream(keyFileName);
        ObjectInputStream objectInputStream = new ObjectInputStream(new BufferedInputStream(inputStream));
        
        try {

            BigInteger modulus = (BigInteger) objectInputStream.readObject();
            BigInteger exponent = (BigInteger) objectInputStream.readObject();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            
            //Assigning respective values to the Public and Private Keys
            if (keyFileName.startsWith("public"))
                key = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
            
                else
                key = keyFactory.generatePrivate(new RSAPrivateKeySpec(modulus, exponent));
        }
            
        catch (Exception e) {
            e.printStackTrace();
        }
            
        finally {
            objectInputStream.close();
        }

        return key;
    }

    public static void keyPairGenerate()  throws Exception {
        // Get an instance of the RSA-512 key generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);

        // Generate the KeyPair
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Get the public and private key
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        // Get the RSAPublicKeySpec and RSAPrivateKeySpec
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
        RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
        
        // Saving the Keys to the file
        saveKeyToFile("public.key", publicKeySpec.getModulus(), publicKeySpec.getPublicExponent());
        saveKeyToFile("private.key", privateKeySpec.getModulus(), privateKeySpec.getPrivateExponent());

        System.out.println("----------------------------------------");
        System.out.println("Public Key generated and saved:");
        System.out.println(publicKey);
        System.out.println("----------------------------------------");
        System.out.println("Private Key generated and saved:");
        System.out.println(privateKey);
        System.out.println("----------------------------------------");

    }

    public static byte[] RSAencrypt(String plainText) throws Exception {
        //Get Public Key Values from File
        Key publicKey = readKeyFromFile("public.key");

        // Get Cipher Instance
        Cipher RSAcipher = Cipher.getInstance("RSA");

        // Initialize Cipher for ENCRYPT_MODE
        RSAcipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Perform Encryption
        byte[] cipherText = RSAcipher.doFinal(plainText.getBytes());

        return cipherText;
    }

    public static String RSAdecrypt(byte[] cipherTextArray) throws Exception {
        //Get Private Key Values from File
        Key privateKey = readKeyFromFile("private.key");

        // Get Cipher Instance
        Cipher RSAcipher = Cipher.getInstance("RSA");

        // Initialize Cipher for DECRYPT_MODE
        RSAcipher.init(Cipher.DECRYPT_MODE, privateKey);

        // Perform Decryption
        byte[] decryptedTextArray = RSAcipher.doFinal(cipherTextArray);

        return new String(decryptedTextArray);
    }
}

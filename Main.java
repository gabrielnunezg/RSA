import java.util.Scanner;
import java.util.Base64;

public class Main {
    public static void main(String[] args) {

        Scanner keyboard = new Scanner(System.in);
        try {
            System.out.println("RSA Encryption and Decryption ALgorithm");
            System.out.println("Please Enter Message to Encrypt");
            String cipherText = keyboard.nextLine();
            int textLength = cipherText.length();

            // Text Bit :ength Validation (RSA-512 accepts messages up to 53 bits long)
            while (textLength > 54) {
                System.out.println("RSA does not accept source messages longer than 53 bytes");
                System.out.println("Message lenght in bytes: " + textLength);
                cipherText = keyboard.nextLine();
                textLength = cipherText.length();
            }

            System.out.println("Accepted Message Length. Message: " + cipherText);

            //Generate KeyPair and Save them in Individual Files
            RSA.keyPairGenerate();

            // Encryption
            byte[] cipherTextArray = RSA.RSAencrypt(cipherText);
            String encryptedText = Base64.getEncoder().encodeToString(cipherTextArray);
            System.out.println("Encrypted Text : " + encryptedText);
    
            // Decryption
            String decryptedText = RSA.RSAdecrypt(cipherTextArray);
            System.out.println("DeCrypted Text : " + decryptedText);
        }

        catch (Exception e) {
            e.printStackTrace();
        }
    }
}

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;

public class IdentityLedger {

    private static ArrayList<String> blockchainLedger = new ArrayList<>();
    
    public static void main(String[] args) {
        try {
            System.out.println("--- INITIALIZING DECENTRALIZED IDENTITY SYSTEM ---");
            
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair authorityKeyPair = keyGen.generateKeyPair();
            PrivateKey authorityPrivateKey = authorityKeyPair.getPrivate();
            PublicKey authorityPublicKey = authorityKeyPair.getPublic();
            
            System.out.println("Trusted Authority Keys successfully generated.");

            String rawUserIdentityData = "Name: Alice Smith, DOB: 05/12/1998, ID_NUM: 987654321";
            
            String identityHash = calculateSHA256(rawUserIdentityData);
            System.out.println("\n[User Side] Private ID Document Hash created: " + identityHash);

            String digitalSignature = signData(identityHash, authorityPrivateKey);
            System.out.println("[Authority Side] DMV digitally signed the identity hash.");

            blockchainLedger.add(digitalSignature);
            System.out.println("[Ledger Side] Anchor Successful. Signed credential added to blockchain.");

            System.out.println("\n--- VERIFICATION AT A THIRD-PARTY BANK ---");
            
            String presentedData = "Name: Alice Smith, DOB: 05/12/1998, ID_NUM: 987654321";
            String presentedHash = calculateSHA256(presentedData);
            
            String blockRecord = blockchainLedger.get(0);
            
            boolean isVerified = verifySignature(presentedHash, blockRecord, authorityPublicKey);
            
            System.out.println("Verification Result: Was this ID approved by the DMV? -> " + isVerified);
            
            System.out.println("\n--- SECURITY TAMPER TEST ---");
            String tamperedData = "Name: Alice Smith, DOB: 05/12/1990, ID_NUM: 987654321"; // Changed year
            String tamperedHash = calculateSHA256(tamperedData);
            
            boolean isTamperedVerified = verifySignature(tamperedHash, blockRecord, authorityPublicKey);
            System.out.println("Tampered Verification Result: Is forged ID approved? -> " + isTamperedVerified);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String calculateSHA256(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static String signData(String data, PrivateKey privateKey) throws Exception {
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign(privateKey);
        rsa.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = rsa.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    private static boolean verifySignature(String data, String signatureBase64, PublicKey publicKey) throws Exception {
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initVerify(publicKey);
        rsa.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
        return rsa.verify(signatureBytes);
    }
}

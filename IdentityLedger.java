import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;

public class IdentityLedger {

    // Simulating a simple ledger of verified identity hashes
    private static ArrayList<String> blockchainLedger = new ArrayList<>();
    
    public static void main(String[] args) {
        try {
            System.out.println("--- INITIALIZING DECENTRALIZED IDENTITY SYSTEM ---");
            
            // 1. Generate Cryptographic Keys for the Trusted Authority (e.g., DMV)
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair authorityKeyPair = keyGen.generateKeyPair();
            PrivateKey authorityPrivateKey = authorityKeyPair.getPrivate();
            PublicKey authorityPublicKey = authorityKeyPair.getPublic();
            
            System.out.println("Trusted Authority Keys successfully generated.");

            // 2. The User's Raw Identity Data (kept private locally)
            String rawUserIdentityData = "Name: Alice Smith, DOB: 05/12/1998, ID_NUM: 987654321";
            
            // 3. Create a cryptographic fingerprint (Hash) of the identity document
            String identityHash = calculateSHA256(rawUserIdentityData);
            System.out.println("\n[User Side] Private ID Document Hash created: " + identityHash);

            // 4. The Authority signs the hash using their Private Key
            String digitalSignature = signData(identityHash, authorityPrivateKey);
            System.out.println("[Authority Side] DMV digitally signed the identity hash.");

            // 5. Anchor the Signature to the Blockchain Ledger
            // In a real blockchain, this string would be the 'Data' payload inside a Block
            blockchainLedger.add(digitalSignature);
            System.out.println("[Ledger Side] Anchor Successful. Signed credential added to blockchain.");

            // ==========================================
            // VERIFICATION PHASE (e.g., A Bank checking Alice's ID)
            // ==========================================
            System.out.println("\n--- VERIFICATION AT A THIRD-PARTY BANK ---");
            
            // Alice presents her original raw text data and claims it was verified by the DMV
            String presentedData = "Name: Alice Smith, DOB: 05/12/1998, ID_NUM: 987654321";
            String presentedHash = calculateSHA256(presentedData);
            
            // The Bank fetches the signed ledger record from the blockchain
            String blockRecord = blockchainLedger.get(0);
            
            // The Bank verifies if the block record matches the hash using the DMV's Public Key
            boolean isVerified = verifySignature(presentedHash, blockRecord, authorityPublicKey);
            
            System.out.println("Verification Result: Was this ID approved by the DMV? -> " + isVerified);
            
            // ==========================================
            // TAMPER TEST (What if Alice tries to change her DOB?)
            // ==========================================
            System.out.println("\n--- SECURITY TAMPER TEST ---");
            String tamperedData = "Name: Alice Smith, DOB: 05/12/1990, ID_NUM: 987654321"; // Changed year
            String tamperedHash = calculateSHA256(tamperedData);
            
            boolean isTamperedVerified = verifySignature(tamperedHash, blockRecord, authorityPublicKey);
            System.out.println("Tampered Verification Result: Is forged ID approved? -> " + isTamperedVerified);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Helper: Compute SHA-256 Hash
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

    // Helper: Sign data using RSA Private Key
    private static String signData(String data, PrivateKey privateKey) throws Exception {
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign(privateKey);
        rsa.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = rsa.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    // Helper: Verify data signature using RSA Public Key
    private static boolean verifySignature(String data, String signatureBase64, PublicKey publicKey) throws Exception {
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initVerify(publicKey);
        rsa.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
        return rsa.verify(signatureBytes);
    }
}

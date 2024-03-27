package pt.tecnico.sirs.MediTrack;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;


public class GenerateSymmetricKey {

    private static final String SYMMETRIC_KEY_BASE_ALIAS = "MediTrackSymmetricKey";
    private static final String KEYSTORE_FILE_PATH = "src/main/java/pt/tecnico/sirs/MediTrack/Keys/keystore1.jks";
    private static final String KEYSTORE_PASSWORD = "meditrack";

    public static void generateAndSaveSymmetricKey(String patientName) {
        try {
            // Ensure the directory exists, create it if not
            Path filePath = Paths.get(KEYSTORE_FILE_PATH);
        
            // Rest of your code
            Path directoryPath = filePath.getParent();
            if (!Files.exists(directoryPath)) {
                Files.createDirectories(directoryPath);
            }
    
            // Generate a symmetric key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey symmetricKey = keyGenerator.generateKey();
    
            // Load or create the KeyStore
            KeyStore keyStore;
            char[] keystorePasswordArray = KEYSTORE_PASSWORD.toCharArray();
            try {
                keyStore = KeyStore.getInstance("JCEKS");
                if (Files.exists(Paths.get(KEYSTORE_FILE_PATH))) {
                    keyStore.load(new FileInputStream(KEYSTORE_FILE_PATH), keystorePasswordArray);
                } else {
                    keyStore.load(null, keystorePasswordArray);
                }
            } catch (NoSuchAlgorithmException | CertificateException e) {
                throw new RuntimeException("Error loading KeyStore", e);
            }
    

            // Save the symmetric key to KeyStore with patient-specific alias
            String symmetricKeyAlias = SYMMETRIC_KEY_BASE_ALIAS + "_" + patientName;
            KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(symmetricKey);
            keyStore.setEntry(symmetricKeyAlias, secretKeyEntry, new KeyStore.PasswordProtection(keystorePasswordArray));

    
            try (FileOutputStream fos = new FileOutputStream(KEYSTORE_FILE_PATH)) {
                keyStore.store(fos, keystorePasswordArray);
            }
    
            System.out.println("Symmetric key generated and saved to KeyStore successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static SecretKey readSymmetricKeyFromKeyStore(String patientName) {
        try {

            KeyStore keyStore = KeyStore.getInstance("JCEKS");
            char[] keystorePasswordArray = KEYSTORE_PASSWORD.toCharArray();
            keyStore.load(new FileInputStream(KEYSTORE_FILE_PATH), keystorePasswordArray);

            String symmetricKeyAlias = SYMMETRIC_KEY_BASE_ALIAS + "_" + patientName;
            return (SecretKey) keyStore.getKey(symmetricKeyAlias, keystorePasswordArray);

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
            System.out.println("Error reading symmetric key from KeyStore");
            e.printStackTrace();
            return null;
        }
    }

}

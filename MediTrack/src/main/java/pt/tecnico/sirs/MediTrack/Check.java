package pt.tecnico.sirs.MediTrack;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import pt.tecnico.sirs.MediTrack.GenerateKeyPair;

public class Check {

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    
    public static Boolean check(JsonObject unprotectedDocument) {
        try {
            // Get the consultationRecords array
            JsonArray consultationRecords = unprotectedDocument.getAsJsonObject("patient").getAsJsonArray("consultationRecords");
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);

            // Iterate through consultationRecords to find the entry with the specified doctorName
            for (JsonElement recordElement : consultationRecords) {
                JsonObject doctor_record = recordElement.getAsJsonObject();
                String doctorName = doctor_record.get("doctorName").getAsString();

                // Step 1: Get the signed hash
                JsonElement signatureElement = doctor_record.get("signature");
                if (signatureElement == null) {
                    System.out.println("Signature is null. Cannot verify the document.");
                    return false;
                }

                String signature_String = signatureElement.getAsString();
                if (signature_String == null) {
                    System.out.println("Signature is null. Cannot verify the document.");
                    return false;
                }

                byte[] signedHash = Base64.getDecoder().decode(signature_String);

                

                // Step 2: Get the hashed data
                doctor_record.remove("signature"); // minus the signature
                MessageDigest digest = MessageDigest.getInstance("SHA-256");

                Gson gson = new Gson();
                String doctor_record_string = gson.toJson(doctor_record);
                byte[] doctor_record_bytes = doctor_record_string.getBytes(StandardCharsets.UTF_8);
                byte[] hashedData = digest.digest(doctor_record_bytes);

                // Step 3: Get the doctor public key
                KeyPair keyPair = GenerateKeyPair.readKeyPairFromKeystore(doctorName, "meditrack");
                PublicKey doctor_public_key = keyPair.getPublic();

                // Step 4: Verify the signature
                signature.initVerify(doctor_public_key);
                signature.update(hashedData);
                boolean isValid = signature.verify(signedHash);

                if (!isValid) {
                    return isValid;
                }
            }

            JsonObject copy_document = unprotectedDocument;

            JsonArray consultationRecordsArray = copy_document.getAsJsonObject("patient")
                    .getAsJsonArray("consultationRecords");

            for (int i = 0; i < consultationRecordsArray.size(); i++) {
                JsonObject doctor_record = consultationRecordsArray.get(i).getAsJsonObject();
                doctor_record.remove("signature"); // minus the signature
                doctor_record.remove("timestamp"); // minus the timestamp
                doctor_record.remove("nonce"); // minus the nonce

                consultationRecordsArray.set(i, doctor_record);
            }

            // Step 1: Get the signed hash
            String signatureString = copy_document.get("signatureHospital").getAsString();
            byte[] signedHash = Base64.getDecoder().decode(signatureString);

            copy_document.remove("signatureHospital");

            Gson gson = new Gson();
            String copy_document_string = gson.toJson(copy_document);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            
            byte[] document_bytes = copy_document_string.getBytes(StandardCharsets.UTF_8);
            byte[] hashedData = digest.digest(document_bytes);


            KeyPair keyPair = GenerateKeyPair.readKeyPairFromKeystore("Hospital", "meditrack");
            PublicKey hospitalPublicKey = keyPair.getPublic();

            signature.initVerify(hospitalPublicKey);
            signature.update(hashedData);
            boolean isValid = signature.verify(signedHash);

            if (!isValid) {
                return isValid;
            }

            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}

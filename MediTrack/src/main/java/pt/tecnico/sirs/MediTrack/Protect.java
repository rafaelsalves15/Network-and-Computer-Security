package pt.tecnico.sirs.MediTrack;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.*;
import java.time.Instant;

public class Protect {

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final int SYMMETRIC_KEY_LENGTH = 256;

    private static final Gson gson = new Gson();

    public static byte[] protect(String document, PublicKey receiverPublicKey, PrivateKey receiverPrivateKey,
            String doctorName, String patientName, PublicKey patientPublicKey) throws Exception {

        SecretKey symmetricKey;

        symmetricKey = GenerateSymmetricKey.readSymmetricKeyFromKeyStore(patientName);

        //Getting hospital private key
        KeyPair keyPair = GenerateKeyPair.readKeyPairFromKeystore("Hospital", "meditrack");
        PrivateKey HospitalPrivateKey = keyPair.getPrivate();

        JsonObject doc2 = gson.fromJson(document, JsonObject.class);
        String doc3 = gson.toJson(doc2);

        byte[] signatureBytesHospital = sign(doc3, HospitalPrivateKey);    
        String signed_hospital_document = addSignatureHospital(doc3, signatureBytesHospital);   

        
        // Step 0: Get the doctor record to sign
        String doctor_record = getDoctorRecord(signed_hospital_document, doctorName);

        // Check if the doctor_record is found
        if (doctor_record != null) {
            // Step 1: Add Freshness
            String fresh_record = addFreshnessToDoctorsRecords(doctor_record);

            // Step 2: Sign the original document with the private key
            byte[] signatureBytes = sign(fresh_record, receiverPrivateKey);

            // Step 3: Add the doctor signature to the document
            String signed_fresh_record = addSignature(fresh_record, signatureBytes);

            // Convert the JSON strings to JsonObject
            JsonObject originalDocumentJson = gson.fromJson(signed_hospital_document, JsonObject.class);
            JsonObject signedFreshRecordJson = gson.fromJson(signed_fresh_record, JsonObject.class);


            // Get the "consultationRecords" array from the original document
            JsonArray consultationRecordsArray = originalDocumentJson.getAsJsonObject("patient")
                    .getAsJsonArray("consultationRecords");

            // Replace the specific consultation record in the original document
            for (int i = 0; i < consultationRecordsArray.size(); i++) {
                JsonObject consultationRecord = consultationRecordsArray.get(i).getAsJsonObject();
                if (doctorName.equals(consultationRecord.get("doctorName").getAsString())) {
                    consultationRecordsArray.set(i, signedFreshRecordJson);
                    break;  // Stop iterating once the record is replaced
                }
            }

            String combinedDocument = gson.toJson(originalDocumentJson);

            // Step 4.1: Encrypt the symmetric key with the receiver's public key
            Cipher asymmetricCipher = Cipher.getInstance(KEY_ALGORITHM);
            asymmetricCipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
            byte[] encryptedSymmetricKey = asymmetricCipher.doFinal(symmetricKey.getEncoded());

            // Step 4.2: Encrypt the symmetric key with the receiver's public key
            Cipher asymmetricCipher2 = Cipher.getInstance(KEY_ALGORITHM);
            asymmetricCipher2.init(Cipher.ENCRYPT_MODE, patientPublicKey);
            byte[] encryptedSymmetricKey2 = asymmetricCipher2.doFinal(symmetricKey.getEncoded());

            // Step 5: Encrypt the SIGNED document with the symmetric key
            Cipher symmetricCipher = Cipher.getInstance(TRANSFORMATION);
            symmetricCipher.init(Cipher.ENCRYPT_MODE, symmetricKey);

            JsonObject signed_fresh_document_json = gson.fromJson(combinedDocument, JsonObject.class);

            String encrypted = encrypt_values(signed_fresh_document_json, symmetricCipher);
            System.out.println("-----------------------------");
            System.out.println("Encrypted Document : " + encrypted);
            System.out.println("-----------------------------");
            byte[] encryptedSignedDocument = encrypted.getBytes(StandardCharsets.UTF_8);

            // Step 6: Combine the encrypted symmetric key and encrypted signed document
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            try {
                outputStream.write(encryptedSymmetricKey);
                outputStream.write(encryptedSignedDocument);
                outputStream.write(new byte[]{(byte) 0x49, (byte) 0x96, (byte) 0x02, (byte) 0xd2});
                outputStream.write(encryptedSymmetricKey2);
                outputStream.write(encryptedSignedDocument);
            } catch (IOException e) {
                e.printStackTrace();
            }
            // System.out.println(outputStream);
            return outputStream.toByteArray();
        } else {
            System.out.println("Doctor record not found for doctorName: " + doctorName);
            return null;
        }
    }

    // Step 1: Sign the document using the private key
    private static byte[] sign(String document, PrivateKey privateKey) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedData = digest.digest(document.getBytes(StandardCharsets.UTF_8));
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(hashedData);

        return signature.sign();
    }

    private static String getDoctorRecord(String jsonString, String doctorName) {
        try {
            // Parse the JSON string
            JsonObject jsonObject = gson.fromJson(jsonString, JsonObject.class);

            // Check if "patient" is a JsonObject or a String
            if (jsonObject.has("patient") && jsonObject.get("patient").isJsonObject()) {
                // Get the consultationRecords array
                JsonArray consultationRecords = jsonObject.getAsJsonObject("patient")
                        .getAsJsonArray("consultationRecords");

                // Iterate through consultationRecords to find the entry with the specified doctorName
                for (int i = 0; i < consultationRecords.size(); i++) {
                    JsonObject record = consultationRecords.get(i).getAsJsonObject();
                    if (doctorName.equals(record.get("doctorName").getAsString())) {
                        return gson.toJson(record);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String addSignature(String jsonString, byte[] signatureBytes) {
        try {
            // Parse the JSON string
            JsonObject jsonObject = gson.fromJson(jsonString, JsonObject.class);
            jsonObject.addProperty("signature", Base64.getEncoder().encodeToString(signatureBytes));
            // Convert back to JSON string
            return gson.toJson(jsonObject);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String addSignatureHospital(String jsonString, byte[] signatureBytes) {
        try {
            // Parse the JSON string
            JsonObject jsonObject = gson.fromJson(jsonString, JsonObject.class);
            
            // Check if the "signatureHospital" property already exists
            if (jsonObject.has("signatureHospital")) {
                jsonObject.addProperty("signatureHospital", Base64.getEncoder().encodeToString(signatureBytes));
            } else {
                // If it doesn't exist, add the property
                jsonObject.addProperty("signatureHospital", Base64.getEncoder().encodeToString(signatureBytes));
            }
    
            // Convert back to JSON string
            return gson.toJson(jsonObject);
    
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    

    private static String encrypt_values(JsonObject jsonObject, Cipher symmetricCipher) {
        for (String key : jsonObject.keySet()) {
            if (!key.equals("name")) { // Skip updating "name"
                JsonElement value = jsonObject.get(key);

                if (value.isJsonObject()) {
                    // Recursive call for nested objects
                    encrypt_values(value.getAsJsonObject(), symmetricCipher);
                } else if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
                    byte[] originalBytes = value.getAsString().getBytes(StandardCharsets.UTF_8);
                    try {
                        byte[] encryptedBytes = symmetricCipher.doFinal(originalBytes);
                        jsonObject.addProperty(key, Base64.getEncoder().encodeToString(encryptedBytes));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } else if (value.isJsonArray()) {

                    JsonArray jsonArray = value.getAsJsonArray();
                    for (int i = 0; i < jsonArray.size(); i++) {
                        JsonElement arrayElement = jsonArray.get(i);
                        if (arrayElement.isJsonObject()) {

                            encrypt_values(arrayElement.getAsJsonObject(), symmetricCipher);
                        } else if (arrayElement.isJsonPrimitive() && arrayElement.getAsJsonPrimitive().isString()) {
                            byte[] originalBytes = arrayElement.getAsString().getBytes(StandardCharsets.UTF_8);
                            try {
                                byte[] encryptedBytes = symmetricCipher.doFinal(originalBytes);
                                jsonArray.set(i, new JsonPrimitive(Base64.getEncoder().encodeToString(encryptedBytes)));
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }

                    }
                }
            }
        }

        return gson.toJson(jsonObject);
    }

    private static String addFreshnessToDoctorsRecords(String jsonString) {
        try {
            // Parse the JSON string using Gson's JsonObject
            JsonObject jsonObject = gson.fromJson(jsonString, JsonObject.class);

            // Add or update the "timestamp" field for freshness
            long timestamp = Instant.now().toEpochMilli();
            jsonObject.addProperty("timestamp", timestamp);

            // Add or update the "nonce" field for freshness
            jsonObject.addProperty("nonce", generateNonce());

            return gson.toJson(jsonObject);

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error in freshness");
        }
        return jsonString; // Return the original JSON string if any exception occurs
    }

    public static byte[] grant_access(byte[] protectedDocument, String patientName, PublicKey sharePublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        SecretKey symmetricKey;
                
        symmetricKey = GenerateSymmetricKey.readSymmetricKeyFromKeyStore(patientName);
        
        // Ensure symmetric key length is a multiple of 16 (block size for AES)
        int symmetricKeyLength = (SYMMETRIC_KEY_LENGTH); // Convert bits to bytes

        int encryptedDocumentLength = protectedDocument.length;
        

        byte[] previous = Arrays.copyOfRange(protectedDocument, 0, symmetricKeyLength);
        byte[] encryptedSignedDocument = Arrays.copyOfRange(protectedDocument, symmetricKeyLength,
                symmetricKeyLength + encryptedDocumentLength - symmetricKeyLength);

        // Encrypt the symmetric key with the new user public key
        Cipher asymmetricCipher = Cipher.getInstance(KEY_ALGORITHM);
        asymmetricCipher.init(Cipher.ENCRYPT_MODE, sharePublicKey);
        byte[] encryptedSymmetricKey = asymmetricCipher.doFinal(symmetricKey.getEncoded());

        // Step 6: Combine the encrypted symmetric key and encrypted signed document
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(encryptedSymmetricKey);
            outputStream.write(encryptedSignedDocument);
        } catch (IOException e) {
            e.printStackTrace();
        }
        // System.out.println(outputStream);
        return outputStream.toByteArray();

    }

    private static String generateNonce() {
        byte[] nonceBytes = new byte[16];
        new SecureRandom().nextBytes(nonceBytes);
        return Base64.getEncoder().encodeToString(nonceBytes);
    }
}
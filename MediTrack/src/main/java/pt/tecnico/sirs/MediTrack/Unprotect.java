package pt.tecnico.sirs.MediTrack;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Base64;

public class Unprotect {

    private static final int SYMMETRIC_KEY_LENGTH = 256;
    private static final String KEY_ALGORITHM = "RSA";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String ENCRYPTION_ALGORITHM = "AES";

    private static final Gson gson = new Gson();

    public static JsonObject unprotect(byte[] protectedDocument, PublicKey receiverPublicKey, PrivateKey receiverPrivateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

        // Ensure symmetric key length is a multiple of 16 (block size for AES)
        int symmetricKeyLength = (SYMMETRIC_KEY_LENGTH); // Convert bits to bytes

        // Ensure encrypted document length is a multiple of 16
        int encryptedDocumentLength = protectedDocument.length;

        byte[] encryptedSymmetricKey = Arrays.copyOfRange(protectedDocument, 0, symmetricKeyLength);
        byte[] encryptedSignedDocument = Arrays.copyOfRange(protectedDocument, symmetricKeyLength,
                symmetricKeyLength + encryptedDocumentLength - symmetricKeyLength);

        // Step 1: Decrypt the symmetric key with the receiver's private key
        Cipher asymmetricCipher = Cipher.getInstance(KEY_ALGORITHM);
        asymmetricCipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);
        byte[] decryptedSymmetricKey = asymmetricCipher.doFinal(encryptedSymmetricKey);

        // Step 2: Decrypt the signed document with the decrypted symmetric key
        Cipher symmetricCipher = Cipher.getInstance(TRANSFORMATION);
        SecretKey symmetricKey = new SecretKeySpec(decryptedSymmetricKey, ENCRYPTION_ALGORITHM);
        symmetricCipher.init(Cipher.DECRYPT_MODE, symmetricKey);

        // Convert the decrypted document to a JsonObject
        JsonObject decryptedJson = gson.fromJson(new String(encryptedSignedDocument, StandardCharsets.UTF_8),
                JsonObject.class);

        // Decrypt the values
        decryptValues(decryptedJson, symmetricCipher);

        return decryptedJson;
    }

    private static void decryptValues(JsonObject jsonObject, Cipher symmetricCipher) {
        for (String key : jsonObject.keySet()) {
            if (!key.equals("name")) { // Skip updating "name"
                JsonElement value = jsonObject.get(key);

                if (value.isJsonObject()) {
                    // Recursive call for nested objects
                    decryptValues(value.getAsJsonObject(), symmetricCipher);
                } else if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
                    byte[] encryptedBytes = Base64.getDecoder().decode(value.getAsString());
                    try {
                        byte[] decryptedBytes = symmetricCipher.doFinal(encryptedBytes);
                        jsonObject.addProperty(key, new String(decryptedBytes, StandardCharsets.UTF_8));
                    } catch (IllegalBlockSizeException | BadPaddingException e) {
                        e.printStackTrace();
                    }
                } else if (value.isJsonArray()) {
                    // Handle JsonArray
                    JsonArray jsonArray = value.getAsJsonArray();
                    for (int i = 0; i < jsonArray.size(); i++) {
                        JsonElement arrayElement = jsonArray.get(i);
                        if (arrayElement.isJsonObject()) {
                            // Recursive call for nested objects within the array
                            decryptValues(arrayElement.getAsJsonObject(), symmetricCipher);
                        } else if (arrayElement.isJsonPrimitive() && arrayElement.getAsJsonPrimitive().isString()) {
                            byte[] encryptedBytes = Base64.getDecoder().decode(arrayElement.getAsString());
                            try {
                                byte[] decryptedBytes = symmetricCipher.doFinal(encryptedBytes);
                                jsonArray.set(i, gson.toJsonTree(new String(decryptedBytes, StandardCharsets.UTF_8)));
                            } catch (IllegalBlockSizeException | BadPaddingException e) {
                                e.printStackTrace();
                            }
                        }
                        // TODO: handle other types if necessary
                    }
                }
            }
        }
    }
}
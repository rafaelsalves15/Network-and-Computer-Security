package pt.tecnico.sirs.MediTrack;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonIOException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

public class CommandLineInterface {
   
    private static final String SYMMETRIC_KEY_BASE_ALIAS = "MediTrackSymmetricKey_";
    private static final String KEY_DIR_PATH = "src/main/java/pt/tecnico/sirs/MediTrack/Keys/";
    public static void main(String[] args) throws Exception {

        GenerateKeyPair.generator("Hospital");


        Scanner scanner = new Scanner(System.in);
        String loggedInUser = null;
        while (true) {
            System.out.println("Available commands: help, register, login, create, update, delete, protect, check, unprotect, grant_access, share, read, exit");
            System.out.print("Enter command: ");
            String input = scanner.nextLine().trim();
            
            // Split the input into parts
            String[] parts = input.split("\\s+");
            String command = parts[0].toLowerCase();
            
            switch (command) {
                case "register":
                    registerUser(scanner);
                    break;
                case "login":
                    String user = loginUser(scanner);
                    if (user != null){
                        loggedInUser = user;
                    }
                    break;
                case "create":
                    if (isLoggedIn(loggedInUser)) {
                        createDocument(scanner , loggedInUser);
                    } else {
                        System.out.println("You need to be logged in to create a document.");
                    }
                    break;
                case "update":
                    if (isLoggedIn(loggedInUser) && parts.length >= 2) {
                        updateDocument(scanner,loggedInUser ,parts[1]);
                    } else {
                        System.out.println("Invalid command. Usage: update <Patient Name>");
                        System.out.println("Or you are not logged in.");
                    }
                    break;

                case "protect":
                    if (isLoggedIn(loggedInUser) && parts.length >= 3) {
                        protectDocument(parts[1], parts[2], loggedInUser);
                    } else {
                        System.out.println("Invalid command. Usage: protect <Original> <Output>");
                        System.out.println("Or you are not logged in.");
                    }
                    break;
                case "check":
                    if (isLoggedIn(loggedInUser) && parts.length >= 2) {
                        checkDocument(parts[1], loggedInUser);
                    } else {
                        System.out.println("Invalid command. Usage: check <Patient Name>");
                        System.out.println("Or you are not logged in.");
                    }
                    break;
                case "unprotect":
                    if (isLoggedIn(loggedInUser) && parts.length >= 3) {
                        unprotectDocument(parts[1], loggedInUser, parts[2]);
                    } else {
                        System.out.println("Invalid command. Usage: unprotect <Output> <Patient Name>");
                        System.out.println("Or you are not logged in.");
                    }
                    break;
                case "delete":
                    if (isLoggedIn(loggedInUser) && parts.length >= 2) {
                        deleteDocument(parts[1]);
                    } else {
                        System.out.println("Invalid command. Usage: delete <Patient Name>");
                        System.out.println("Or you are not logged in.");
                    }
                    break;
                case "grant_access":
                    if (isLoggedIn(loggedInUser) && parts.length >= 3) {
                        if (DatabaseConnector.isUserRegistered(parts[1])){
                            grant_access(loggedInUser, parts[1], parts[2]);
                        } else {
                            System.out.println("The username does not exist");
                        }    
                    } else {
                        System.out.println("Invalid command. Usage: grant_access <New_user> <Patient Name>");
                        System.out.println("Or you are not logged in.");
                    }
                    break;
                case "share":
                    if (isLoggedIn(loggedInUser) && parts.length >= 2) {
                        share(loggedInUser, parts[1]);
                    } else {
                        System.out.println("Invalid command. Usage: share <New_user>");
                        System.out.println("Or you are not logged in.");
                    }
                    break;
                case "read":
                    if (isLoggedIn(loggedInUser) && parts.length >= 2) {
                        read(loggedInUser, parts[1]);
                    } else {
                        System.out.println("Invalid command. Usage: read <Output>");
                        System.out.println("Or you are not logged in.");
                    }
                    break;
                case "help":
                    printHelp();
                    break;
                case "exit":
                    System.out.println("Exiting program...");
                    System.exit(0);
                    break;
                default:
                    System.out.println("Invalid command. Type 'help' for assistance.");
            }
        }
    }

    private static void createDocument(Scanner scanner, String loggedInUser) {
        System.out.println("Creating a new document...");

        try {
            // Prompt user for document details
            System.out.print("Enter patient name: ");
            String patientName = scanner.nextLine().trim();
            System.out.print("Enter patient sex: ");
            String sex = scanner.nextLine().trim();
            System.out.print("Enter patient date of birth (yyyy-MM-dd): ");
            String dateOfBirth = scanner.nextLine().trim();
            System.out.print("Enter patient blood type: ");
            String bloodType = scanner.nextLine().trim();

            // Prompt user for known allergies (comma-separated)
            System.out.print("Enter known allergies (comma-separated): ");
            String knownAllergiesInput = scanner.nextLine().trim();
            String[] knownAllergiesArray = knownAllergiesInput.split(",");
            List<String> knownAllergiesList = Arrays.asList(knownAllergiesArray);

            // Prompt user for consultation records
            List<ConsultationRecord> consultationRecords = new ArrayList<>();

            System.out.print("Enter consultation date: ");
            String date = scanner.nextLine().trim();
            System.out.print("Enter medical speciality: ");
            String medicalSpeciality = scanner.nextLine().trim();
            System.out.print("Enter doctor name: ");
            String doctorName = scanner.nextLine().trim();
            System.out.print("Enter practice: ");
            String practice = scanner.nextLine().trim();
            System.out.print("Enter treatment summary: ");
            String treatmentSummary = scanner.nextLine().trim();

            // Create ConsultationRecord object
            ConsultationRecord record = new ConsultationRecord(date, medicalSpeciality, doctorName, practice, treatmentSummary);
            consultationRecords.add(record);


            // Create patient object
            Patient patient = new Patient(patientName, sex, dateOfBirth, bloodType, knownAllergiesList, consultationRecords);

            // Create a container object to hold patient and consultation records
            Map<String, Object> documentMap = new HashMap<>();
            documentMap.put("patient", patient);

            // Convert document to JSON
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            String jsonDocument = gson.toJson(documentMap);

            // Save the document to the specified path
            String filePath = "src/main/java/pt/tecnico/sirs/MediTrack/NewlyCreatedDocument.json";
            Files.write(Paths.get(filePath), jsonDocument.getBytes());

            // Save the document to the command line
            System.out.println("Document created and saved to: " + filePath);

            // Protect and store the document
            protectDocument(filePath, "output.json", loggedInUser);

            System.out.println("Document protected and stored in the database.");
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error creating document.");
        }
    }


    

    private static void updateDocument(Scanner scanner, String loggedInUser , String patientName) throws Exception {
        System.out.print("Do you want to update patient information or add a consultation record? (patient/record): ");
        String updateOption = scanner.nextLine().trim().toLowerCase();
    
        switch (updateOption) {
            case "patient":
                System.out.println("Updating patient information...");
                updatePatientInformation(scanner, loggedInUser,patientName);
                break;
            case "record":
                addConsultationRecord(scanner, loggedInUser,patientName);
                break;
            default:
                System.out.println("Invalid option. Please choose 'patient' or 'record'.");
        }
    }
    

    private static void protectDocument(String originalFilePath , String outputFilePath ,String doctorName) {
        System.out.println("Protecting document...");

        try {
            // Simulate the sender side
            String originalDocument = new String(Files.readAllBytes(Paths.get(originalFilePath)));

            System.out.println("Original Document");
            System.out.println(originalDocument);

            // Generate Symmetric Key - Generate only ONCE for each different document 
            // Check if we already generated Symmetric Key for this document... if not generate SymmetricKey
            String patientName = extractPatientName(originalDocument);
            System.out.println("Patient Name: " + patientName);

            String keyFileName = SYMMETRIC_KEY_BASE_ALIAS + patientName;
            Path keyFilePath = Path.of(KEY_DIR_PATH, keyFileName + ".key");

            if (!Files.exists(keyFilePath)) { // If theres no SymmetricKey for this document we generate it
                System.out.println("No Symmetric Key for this document. Generating the SymmetricKey...");
                GenerateSymmetricKey.generateAndSaveSymmetricKey(patientName);
            }


            // Read Public and Private keys for the Doctor
            KeyPair keyPair = GenerateKeyPair.readKeyPairFromKeystore(doctorName, "meditrack");
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            KeyPair keyPair2 = GenerateKeyPair.readKeyPairFromKeystore(patientName, "meditrack");
            PublicKey publicKey2 = keyPair2.getPublic();

            byte[] protectedDocument = Protect.protect(originalDocument, publicKey, privateKey, doctorName, patientName, publicKey2);

            // Find the index of the divider in the input data
            int dividerIndex = indexOf(protectedDocument, new byte[]{(byte) 0x49, (byte) 0x96, (byte) 0x02, (byte) 0xd2});

            if (dividerIndex != -1) {
                // Split the input data into two parts
                byte[] part1 = Arrays.copyOfRange(protectedDocument, 0, dividerIndex);
                byte[] part2 = Arrays.copyOfRange(protectedDocument, dividerIndex + 4, protectedDocument.length);

                // Write the two parts to separate files
                try {
                    Files.write(Paths.get(outputFilePath + "_doc.json"), part1);
                    Files.write(Paths.get(outputFilePath + "_pat.json"), part2);

                    // Save protected document to the database
                    if (DatabaseConnector.saveProtectedDocument(patientName + "_D", part1)) {
                        System.out.println("Document protected and saved successfully.");
                    } else {
                        System.out.println("Error saving protected document to the database.");
                    }

                    if (DatabaseConnector.saveProtectedDocument(patientName + "_P", part2)) {
                        System.out.println("Document protected and saved successfully.");
                    } else {
                        System.out.println("Error saving protected document to the database.");
                    }
                } catch (IOException e) {
                    // Handle the exception appropriately (log or throw a custom exception)
                    e.printStackTrace();
                }
            } else {
                System.out.println("Divider not found in the input data.");
            }


            System.out.println("Document protected and saved successfully.");
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error protecting document.");
        }
    }


    private static void unprotectDocument(String outputFilePath, String doctorName, String patientName) {
        System.out.println("Unprotecting document...");
    
        try {
            byte[] encryptedDocument;
    
            if (doctorName.equals(patientName)) {
                // If doctorName equals patientName, fetch the document for both doctor and patient
                encryptedDocument = DatabaseConnector.retrieveProtectedDocument(patientName + "_P");
            } else {
                // Fetch the document for the patient
                encryptedDocument = DatabaseConnector.retrieveProtectedDocument(patientName + "_D");
            }
    
            if (encryptedDocument != null) {
                // read Public and Private keys for the Doctor
                KeyPair keyPair = GenerateKeyPair.readKeyPairFromKeystore(doctorName, "meditrack");
                PublicKey publicKey = keyPair.getPublic();
                PrivateKey privateKey = keyPair.getPrivate();
    
                // Unprotect the document
                JsonObject unprotectedDocument = Unprotect.unprotect(encryptedDocument, publicKey, privateKey);
    
                // Save unprotected document to the specified output file
                Files.write(Paths.get(outputFilePath), unprotectedDocument.toString().getBytes());
    
                System.out.println("Document unprotected and saved successfully.");
            } else {
                System.out.println("Error: No document found in the database for the specified patient and doctor.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error unprotecting document.");
        }
    }

    public static void share(String patientName, String new_user) {
        try {
            // Fetch the encrypted document based on the doctor and patient names
            byte[] encryptedDocument = DatabaseConnector.retrieveProtectedDocument(patientName + "_P");
    
            if (encryptedDocument != null) {
                // Read public and private keys for the doctor
                KeyPair keyPair = GenerateKeyPair.readKeyPairFromKeystore(patientName, "meditrack");
                PublicKey publicKey = keyPair.getPublic();
                PrivateKey privateKey = keyPair.getPrivate();
    
                // Unprotect the document
                JsonObject unprotectedDocument = Unprotect.unprotect(encryptedDocument, publicKey, privateKey);
                System.out.println("Document unprotected and saved successfully.");
    
                // Get patient data
                JsonObject patientData = unprotectedDocument.getAsJsonObject("patient");
    
                // Get the array of consultation records
                JsonArray consultationRecords = patientData.getAsJsonArray("consultationRecords");
    
                // Display patient data
                System.out.println("Patient Data:");
                System.out.println("Name: " + patientData.getAsJsonPrimitive("name").getAsString());
    
                // Display available consultation records to the user
                System.out.println("\nAvailable Consultation Records:");
                for (int i = 0; i < consultationRecords.size(); i++) {
                    JsonObject record = consultationRecords.get(i).getAsJsonObject();
                    System.out.println(i + ": " + record.getAsJsonPrimitive("doctorName").getAsString()
                            + " - " + record.getAsJsonPrimitive("date").getAsString());
                }
    
                Scanner scanner = new Scanner(System.in);
                boolean continueSaving = true;
    
                // Loop to allow the user to select multiple records
                while (continueSaving) {
                    System.out.print("\nEnter the index of the consultation record to save (or -1 to stop): ");
                    int selectedIndex = scanner.nextInt();
    
                    if (selectedIndex == -1) {
                        // User chose to stop saving records
                        continueSaving = false;
                    } else if (selectedIndex >= 0 && selectedIndex < consultationRecords.size()) {
                        // Mark the selected record as "saved"
                        JsonObject selectedRecord = consultationRecords.get(selectedIndex).getAsJsonObject();
                        selectedRecord.addProperty("saved", true);
                        System.out.println("Consultation record saved successfully!");
                    } else {
                        System.out.println("Invalid index. Please try again.");
                    }
                }
    
                // Create a new JsonObject to hold the modified patient data
                JsonObject updatedPatientData = new JsonObject();
    
                // Copy non-array properties from the original patient data
                updatedPatientData.add("name", patientData.get("name"));
                updatedPatientData.add("sex", patientData.get("sex"));
                updatedPatientData.add("dateOfBirth", patientData.get("dateOfBirth"));
                updatedPatientData.add("bloodType", patientData.get("bloodType"));
                updatedPatientData.add("knownAllergies", patientData.get("knownAllergies"));
                // Add any other non-array properties you want to include
    
                // Create a new JsonArray to hold the selected consultation records
                JsonArray updatedConsultationRecords = new JsonArray();
    
                // Loop to add the selected records to the new array
                for (int i = 0; i < consultationRecords.size(); i++) {
                    JsonObject record = consultationRecords.get(i).getAsJsonObject();
    
                    // Check if the "saved" property exists before accessing its value
                    JsonPrimitive savedPrimitive = record.getAsJsonPrimitive("saved");
                    boolean isSaved = (savedPrimitive != null && savedPrimitive.isBoolean()) ? savedPrimitive.getAsBoolean() : false;
    
                    if (isSaved) {
                        updatedConsultationRecords.add(record);
                    }
                }
    
                // Add the new array of selected consultation records to the updated patient data
                updatedPatientData.add("consultationRecords", updatedConsultationRecords);
    
                // Print the updated patient data
                Gson gson = new Gson();
                String updatedJson = gson.toJson(updatedPatientData);
                System.out.println("\nUpdated Patient Data:\n" + updatedJson);

                if (DatabaseConnector.saveProtectedDocument(new_user + "_R", updatedJson.getBytes())) {
                        System.out.println("Document protected and saved successfully.");
                    } else {
                        System.out.println("Error saving protected document to the database.");
                    }
    
            } else {
                System.out.println("Error: No document found in the database for the specified patient and doctor.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error unprotecting document.");
        }
    }
    

    private static void read(String logginUser, String path) {
    
        try {
            byte[] Document;
    
            Document = DatabaseConnector.retrieveProtectedDocument(logginUser + "_R");

    
    
            String result = new String(Document, StandardCharsets.UTF_8);

            // Save unprotected document to the specified output file
            Files.write(Paths.get(path), result.toString().getBytes());
    
            System.out.println("Document saved successfully.");
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error saving the document.");
        }
    }

    


    private static void checkDocument(String patientName, String doctorName) {
        System.out.println("Checking document...");

        try {        
            byte[] encryptedDocument;

            if (doctorName.equals(patientName)) {
                // If doctorName equals patientName, fetch the document for both doctor and patient
                encryptedDocument = DatabaseConnector.retrieveProtectedDocument(patientName + "_P");
            } else {
                // Fetch the document for the patient
                encryptedDocument = DatabaseConnector.retrieveProtectedDocument(patientName + "_D");
            }

            // read Public and Private keys for the Doctor
            KeyPair keyPair = GenerateKeyPair.readKeyPairFromKeystore(doctorName, "meditrack");
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Unprotect the document
            JsonObject unprotectedDocument = Unprotect.unprotect(encryptedDocument, publicKey, privateKey);

            // Convert the byte array to a String (assuming it's a JSON string)
            String documentString = new String(unprotectedDocument.toString());

            // Use Gson to parse the JSON string into a JsonObject
            Gson gson = new Gson();
            JsonObject document = gson.fromJson(documentString, JsonObject.class);

            // Check the document
            boolean checkedDocument = Check.check(document);

            if (checkedDocument) {
                System.out.println("Document integrity verified.");
            } else {
            System.out.println("Document integrity compromised.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error checking document.");
        }
    }

    private static void printHelp() {
        System.out.println("Available commands: help, create, register, login, protect, check, unprotect, exit");
        System.out.println("You can only do create, protect, unprotect and check if you are logged in!");
    }

    private static void registerUser(Scanner scanner) throws Exception {
        // Prompt user for registration details
        System.out.print("Enter username: ");
        String username = scanner.nextLine().trim();
        System.out.print("Enter password: ");
        String password = scanner.nextLine().trim();

        if (DatabaseConnector.isUserRegistered(username)) {
            System.out.println("User already registered!");
        } else {
            boolean registrationResult = DatabaseConnector.registerUser(username, password);
            if (registrationResult) {
                System.out.println("User registered successfully!");
            } else {
                System.out.println("Failed to register user.");
            }
        }

        GenerateKeyPair.generator(username);
    }

    private static String loginUser(Scanner scanner) {
        // Prompt user for login details
        System.out.print("Enter username: ");
        String username = scanner.nextLine().trim();
        System.out.print("Enter password: ");
        String password = scanner.nextLine().trim();

        // Login user
        if (DatabaseConnector.loginUser(username, password)) {
            System.out.println("Login successful.");
            return username;
        } else {
            System.out.println("Invalid username or password.");
            return null;
        }
    }

    private static void deleteDocument(String patientName) {
        boolean deletionResult = DatabaseConnector.deleteProtectedDocuments(patientName);
    
        if (deletionResult) {
            System.out.println("Document deleted successfully.");
        } else {
            System.out.println("Failed to delete document.");
        }
    }

    private static void grant_access(String user, String share, String patientName) throws Exception {
        
        byte[] encryptedDocument;

        if (user.equals(patientName)) {
            // If doctorName equals patientName, fetch the document for both doctor and patient
            encryptedDocument = DatabaseConnector.retrieveProtectedDocument(patientName + "_P");
        } else {
            // Fetch the document for the patient
            encryptedDocument = DatabaseConnector.retrieveProtectedDocument(patientName + "_D");
        }

        
        KeyPair keyPair = GenerateKeyPair.readKeyPairFromKeystore(share, "meditrack");
        PublicKey publicKey = keyPair.getPublic();
                    
        byte[] newDocument = Protect.grant_access(encryptedDocument, patientName, publicKey);


        // Save protected document to the database
        if (DatabaseConnector.saveProtectedDocument(patientName + "_D", newDocument)) {
            System.out.println("Document protected and saved successfully.");
        } else {
            System.out.println("Error saving protected document to the database.");
        }        

    }

// --------------------------------------------------------------------------------------------------------
//                                     Auxiliary Methods
// --------------------------------------------------------------------------------------------------------


    private static int indexOf(byte[] source, byte[] target) {
        for (int i = 0; i < source.length - target.length + 1; i++) {
            boolean match = true;
            for (int j = 0; j < target.length; j++) {
                if (source[i + j] != target[j]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                return i;
            }
        }
        return -1;
    }
   

    private static String extractPatientName(String originalDocument) {
        Gson gson = new Gson();
        try {
            JsonObject originalDocumentJson = gson.fromJson(originalDocument, JsonObject.class);
            JsonObject patientObject = originalDocumentJson.getAsJsonObject("patient");
            return patientObject.get("name").getAsString();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static boolean isLoggedIn(String loggedInUser) {
        return loggedInUser != null;
    }

    private static void updatePatientInformation(Scanner scanner , String loggedInUser ,String patientName) throws Exception {
        
        byte[] encryptedDocument;
                
            if (loggedInUser.equals(patientName)) {
                // If doctorName equals patientName, fetch the document for both doctor and patient
                encryptedDocument = DatabaseConnector.retrieveProtectedDocument(patientName + "_P");
            } else {
                // Fetch the document for the patient
                encryptedDocument = DatabaseConnector.retrieveProtectedDocument(patientName + "_D");
            }

        DatabaseConnector.deleteProtectedDocuments(patientName);
        
        
        // read Public and Private keys for the Doctor/Patient (User)
        KeyPair keyPair = GenerateKeyPair.readKeyPairFromKeystore(loggedInUser, "meditrack");
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        KeyPair keyPair2 = GenerateKeyPair.readKeyPairFromKeystore(patientName, "meditrack");
        PublicKey publicKey2 = keyPair2.getPublic();

        // Unprotect it (it comes protected from the DB)
        JsonObject unprotectedDocument = Unprotect.unprotect(encryptedDocument, publicKey, privateKey);
        String unprotectedDocumentString = unprotectedDocument.toString();


        System.out.println("Current Document Information:");
        System.out.println(unprotectedDocumentString);

        System.out.println("What do you want to update?");
        System.out.println("1. Name");
        System.out.println("2. Sex");
        System.out.println("3. Date of Birth");
        System.out.println("4. Blood Type");
        System.out.println("5. Known Allergies");
        System.out.print("Enter your choice (1, 2, 3, 4, or 5): ");

        String choice = scanner.nextLine().trim();

        switch (choice) {
            case "1":
                System.out.print("Enter new name: ");
                String newName = scanner.nextLine().trim();
                unprotectedDocumentString = updateField(unprotectedDocumentString, "name", newName);
                break;
            case "2":
                System.out.print("Enter new sex: ");
                String newSex = scanner.nextLine().trim();
                unprotectedDocumentString = updateField(unprotectedDocumentString, "sex", newSex);
                break;
            case "3":
                System.out.print("Enter new date of birth (YYYY-MM-DD): ");
                String newDateOfBirth = scanner.nextLine().trim();
                unprotectedDocumentString = updateField(unprotectedDocumentString, "dateOfBirth", newDateOfBirth);
                break;
            case "4":
                System.out.print("Enter new blood type: ");
                String newBloodType = scanner.nextLine().trim();
                unprotectedDocumentString = updateField(unprotectedDocumentString, "bloodType", newBloodType);
                break;
            case "5":
                System.out.print("Enter new known allergy: ");
                String newKnownAllergy = scanner.nextLine().trim();
                unprotectedDocumentString = addKnownAllergy(unprotectedDocumentString, newKnownAllergy);
                break;
            default:
                System.out.println("Invalid choice. Please enter 1, 2, 3, 4, or 5.");
                return;
        }

        // We now have to store the document in the DB - but it must be protected before
        byte[] protectedDocument = Protect.protect(unprotectedDocumentString, publicKey, privateKey, loggedInUser, patientName, publicKey2);
        
        // Find the index of the divider in the input data
        int dividerIndex = indexOf(protectedDocument, new byte[]{(byte) 0x49, (byte) 0x96, (byte) 0x02, (byte) 0xd2});

        if (dividerIndex != -1) {
            // Split the input data into two parts
            byte[] part1 = Arrays.copyOfRange(protectedDocument, 0, dividerIndex);
            byte[] part2 = Arrays.copyOfRange(protectedDocument, dividerIndex + 4, protectedDocument.length);

            // Save protected document to the database
            if (DatabaseConnector.saveProtectedDocument(patientName + "_D", part1)) {
                System.out.println("Document protected and saved successfully.");
            } else {
                System.out.println("Error saving protected document to the database.");
            }

            if (DatabaseConnector.saveProtectedDocument(patientName + "_P", part2)) {
                System.out.println("Document protected and saved successfully.");
            } else {
                System.out.println("Error saving protected document to the database.");
            }
        } else {
            System.out.println("Divider not found in the input data.");
        }
    }

    private static String updateField(String jsonDocument, String fieldName, String newValue) {
        Gson gson = new Gson();
        JsonObject jsonObject = gson.fromJson(jsonDocument, JsonObject.class);
    
        if (jsonObject.has(fieldName)) {
            jsonObject.addProperty(fieldName, newValue);
            System.out.println("Field updated successfully.");
        } else {
            System.out.println("Field not found in the document.");
        }
    
        return jsonObject.toString();
    }
    
    



    private static String addKnownAllergy(String json, String newKnownAllergy) {
        Gson gson = new Gson();
        try {
            JsonObject jsonObject = gson.fromJson(json, JsonObject.class);
            JsonArray knownAllergies = jsonObject.getAsJsonObject("patient").getAsJsonArray("knownAllergies");
            knownAllergies.add(newKnownAllergy);
            return jsonObject.toString();
        } catch (JsonIOException e) {
            System.out.println("Error adding known allergy to JSON.");
            return json;
        }
    }


    private static void addConsultationRecord(Scanner scanner,String loggedInUser , String patientName) throws Exception {
          //Get document from the DB
        byte[] encryptedDocument;
                
            if (loggedInUser.equals(patientName)) {
                // If doctorName equals patientName, fetch the document for both doctor and patient
                encryptedDocument = DatabaseConnector.retrieveProtectedDocument(patientName + "_P");
            } else {
                // Fetch the document for the patient
                encryptedDocument = DatabaseConnector.retrieveProtectedDocument(patientName + "_D");
            }
        
        DatabaseConnector.deleteProtectedDocuments(patientName);
        
        // read Public and Private keys for the Doctor/Patient (User)
        KeyPair keyPair = GenerateKeyPair.readKeyPairFromKeystore(loggedInUser, "meditrack");
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        KeyPair keyPair2 = GenerateKeyPair.readKeyPairFromKeystore(patientName, "meditrack");
        PublicKey publicKey2 = keyPair2.getPublic();

        // Unprotect it (it comes protected from the DB)
        JsonObject unprotectedDocument = Unprotect.unprotect(encryptedDocument, publicKey, privateKey);
        String unprotectedDocumentString = unprotectedDocument.toString();
        
        // Parse the current patient information JSON string to a JsonObject using Gson with ordered serialization
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        JsonObject patientInfo = JsonParser.parseString(unprotectedDocumentString).getAsJsonObject();
    
        
        // Prompt user for consultation record details
        System.out.print("Enter consultation date: ");
        String date = scanner.nextLine().trim();
        System.out.print("Enter medical speciality: ");
        String medicalSpeciality = scanner.nextLine().trim();
        System.out.print("Enter doctor name: ");
        String doctorName = scanner.nextLine().trim();
        System.out.print("Enter practice: ");
        String practice = scanner.nextLine().trim();
        System.out.print("Enter treatment summary: ");
        String treatmentSummary = scanner.nextLine().trim();

        // Create a new consultation record JsonObject
        JsonObject consultationRecord = new JsonObject();
        consultationRecord.addProperty("date", date);
        consultationRecord.addProperty("medicalSpeciality", medicalSpeciality);
        consultationRecord.addProperty("doctorName", doctorName);
        consultationRecord.addProperty("practice", practice);
        consultationRecord.addProperty("treatmentSummary", treatmentSummary);

        // Get the "consultationRecords" array from the patient information
        JsonArray consultationRecords = patientInfo.getAsJsonObject("patient").getAsJsonArray("consultationRecords");

        // Add the new consultation record to the array
        consultationRecords.add(consultationRecord);

        // Update the patient information with the new consultation record
        String updatedPatientInfo = patientInfo.toString();

        // We now have to store the document in the DB - but it must be protected before
        byte[] protectedDocument = Protect.protect(updatedPatientInfo, publicKey, privateKey, loggedInUser, patientName, publicKey2);


        // Find the index of the divider in the input data
        int dividerIndex = indexOf(protectedDocument, new byte[]{(byte) 0x49, (byte) 0x96, (byte) 0x02, (byte) 0xd2});

        if (dividerIndex != -1) {
            // Split the input data into two parts
            byte[] part1 = Arrays.copyOfRange(protectedDocument, 0, dividerIndex);
            byte[] part2 = Arrays.copyOfRange(protectedDocument, dividerIndex + 4, protectedDocument.length);

            // Save protected document to the database
            if (DatabaseConnector.saveProtectedDocument(patientName + "_D", part1)) {
                System.out.println("Document protected and saved successfully.");
            } else {
                System.out.println("Error saving protected document to the database.");
            }

            if (DatabaseConnector.saveProtectedDocument(patientName + "_P", part2)) {
                System.out.println("Document protected and saved successfully.");
            } else {
                System.out.println("Error saving protected document to the database.");
            }
        } else {
            System.out.println("Divider not found in the input data.");
        }
    }
}


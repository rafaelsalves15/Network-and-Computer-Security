USE MediTrack;

-- Create a table for storing documents
CREATE TABLE documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_name VARCHAR(255) NOT NULL,
    json_document BLOB
);

-- Create a table for storing user information
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);


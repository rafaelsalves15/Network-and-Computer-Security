
package pt.tecnico.sirs.MediTrack;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class DatabaseConnector {
    private static final String DB_URL = "jdbc:mariadb://192.168.1.4:3306/MediTrack";
    private static final String DB_USER = "new_user";
    private static final String DB_PASSWORD = "new_password";

    public static Connection connectToDatabase() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }

    public static boolean registerUser(String username, String password) {
        try (Connection connection = connectToDatabase()) {
            String query = "INSERT INTO users (username, password) VALUES (?, ?)";
            try (PreparedStatement statement = connection.prepareStatement(query)) {
                statement.setString(1, username);
                statement.setString(2, password);
                int affectedRows = statement.executeUpdate();
                
                // Grant privileges to the newly registered user
                if (affectedRows > 0) {
                    grantPrivileges(connection, username,password);
                }
                
                return affectedRows > 0;
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    private static void grantPrivileges(Connection connection, String username, String password )  throws SQLException {
        String grantQuery = "GRANT ALL PRIVILEGES ON MediTrack.* TO ?@'%' IDENTIFIED BY ?";
        try (PreparedStatement grantStatement = connection.prepareStatement(grantQuery)) {
            grantStatement.setString(1, username);
            grantStatement.setString(2, password); 
            grantStatement.executeUpdate();
        }
    }

    public static boolean loginUser(String username, String password) {
        try (Connection connection = connectToDatabase()) {
            String query = "SELECT * FROM users WHERE username = ? AND password = ?";
            try (PreparedStatement statement = connection.prepareStatement(query)) {
                statement.setString(1, username);
                statement.setString(2, password);
                try (ResultSet resultSet = statement.executeQuery()) {
                    return resultSet.next();
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean saveProtectedDocument(String patientName, byte[] protectedDocument) {
        try (Connection connection = connectToDatabase()) {
            if (documentExists(connection, patientName)) {
                // If document exists, update it
                String updateQuery = "UPDATE documents SET json_document = ? WHERE patient_name = ?";
                try (PreparedStatement updateStatement = connection.prepareStatement(updateQuery)) {
                    updateStatement.setBytes(1, protectedDocument);
                    updateStatement.setString(2, patientName);
                    int affectedRows = updateStatement.executeUpdate();
                    return affectedRows > 0;
                }
            } else {
                // If document doesn't exist, insert a new record
                String insertQuery = "INSERT INTO documents (patient_name, json_document) VALUES (?, ?)";
                try (PreparedStatement insertStatement = connection.prepareStatement(insertQuery)) {
                    insertStatement.setString(1, patientName);
                    insertStatement.setBytes(2, protectedDocument);
                    int affectedRows = insertStatement.executeUpdate();
                    return affectedRows > 0;
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    private static boolean documentExists(Connection connection, String patientName) throws SQLException {
        String query = "SELECT COUNT(*) FROM documents WHERE patient_name = ?";
        try (PreparedStatement statement = connection.prepareStatement(query)) {
            statement.setString(1, patientName);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getInt(1) > 0;
                }
            }
        }
        return false;
    }
    

    public static byte[] retrieveProtectedDocument(String patientName) {
        try (Connection connection = connectToDatabase()) {
            String query = "SELECT json_document FROM documents WHERE patient_name = ?";
            try (PreparedStatement statement = connection.prepareStatement(query)) {
                statement.setString(1, patientName);
                try (ResultSet resultSet = statement.executeQuery()) {
                    if (resultSet.next()) {
                        return resultSet.getBytes("json_document");
                    }
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean deleteProtectedDocuments(String patientName) {
        try (Connection connection = connectToDatabase()) {
            String query = "DELETE FROM documents WHERE patient_name = ? OR patient_name = ?";
            try (PreparedStatement statement = connection.prepareStatement(query)) {
                // Delete both documents with names "patientName_D" and "patientName_P"
                statement.setString(1, patientName + "_D");
                statement.setString(2, patientName + "_P");
                
                int affectedRows = statement.executeUpdate();
                return affectedRows > 0;
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public static boolean isUserRegistered(String username) {
        try (Connection connection = connectToDatabase()) {
            String query = "SELECT * FROM users WHERE username = ?";
            try (PreparedStatement statement = connection.prepareStatement(query)) {
                statement.setString(1, username);
                try (ResultSet resultSet = statement.executeQuery()) {
                    return resultSet.next();
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }


}

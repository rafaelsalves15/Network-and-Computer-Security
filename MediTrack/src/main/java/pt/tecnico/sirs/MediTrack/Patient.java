package pt.tecnico.sirs.MediTrack;

import java.util.List;

public class Patient {
    private String name;
    private String sex;
    private String dateOfBirth;
    private String bloodType;
    private List<String> knownAllergies;
    private List<ConsultationRecord> consultationRecords;

    public Patient(String name, String sex, String dateOfBirth, String bloodType, List<String> knownAllergies, List<ConsultationRecord> consultationRecords) {
        this.name = name;
        this.sex = sex;
        this.dateOfBirth = dateOfBirth;
        this.bloodType = bloodType;
        this.knownAllergies = knownAllergies;
        this.consultationRecords = consultationRecords;
    }

    public void setConsultationRecords(List<ConsultationRecord> consultationRecords) {
        this.consultationRecords = consultationRecords;
    }
}

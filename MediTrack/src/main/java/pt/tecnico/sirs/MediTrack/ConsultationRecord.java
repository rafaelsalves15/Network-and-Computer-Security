package pt.tecnico.sirs.MediTrack;

public class ConsultationRecord {
    private String date;
    private String medicalSpeciality;
    private String doctorName;
    private String practice;
    private String treatmentSummary;

    public ConsultationRecord(String date, String medicalSpeciality, String doctorName, String practice, String treatmentSummary) {
        this.date = date;
        this.medicalSpeciality = medicalSpeciality;
        this.doctorName = doctorName;
        this.practice = practice;
        this.treatmentSummary = treatmentSummary;
    }

    public String getDate() {
        return date;
    }

    public void setDate(String date) {
        this.date = date;
    }

    public String getMedicalSpeciality() {
        return medicalSpeciality;
    }

    public void setMedicalSpeciality(String medicalSpeciality) {
        this.medicalSpeciality = medicalSpeciality;
    }

    public String getDoctorName() {
        return doctorName;
    }

    public void setDoctorName(String doctorName) {
        this.doctorName = doctorName;
    }

    public String getPractice() {
        return practice;
    }

    public void setPractice(String practice) {
        this.practice = practice;
    }

    public String getTreatmentSummary() {
        return treatmentSummary;
    }

    public void setTreatmentSummary(String treatmentSummary) {
        this.treatmentSummary = treatmentSummary;
    }
}

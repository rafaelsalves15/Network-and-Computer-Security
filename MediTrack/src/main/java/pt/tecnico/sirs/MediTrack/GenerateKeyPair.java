package pt.tecnico.sirs.MediTrack;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;

public class GenerateKeyPair {

    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String KEYSTORE_FILE_PATH = "src/main/java/pt/tecnico/sirs/MediTrack/Keys/keystore2.pfx";

    public static void generator(String username) throws Exception{
        // Add the BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());

        // Initialize a new KeyPair generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(2048);

        // Setup start date to yesterday and end date for 1 year validity
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();

        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        // First step is to create a root certificate
        // First Generate a KeyPair,
        // then a random serial number
        // then generate a certificate using the KeyPair
        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        // Issued By and Issued To same for root certificate
        X500Name rootCertIssuer = new X500Name("CN=root-cert");
        X500Name rootCertSubject = rootCertIssuer;
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER).build(rootKeyPair.getPrivate());
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum, startDate, endDate, rootCertSubject, rootKeyPair.getPublic());

        // Add Extensions
        // A BasicConstraint to mark root certificate as CA certificate
        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));

        // Create a cert holder and export to X509Certificate
        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(rootCertHolder);

        //writeCertToFileBase64Encoded(rootCert, KEYSTORE_FILE_PATH);
        //exportKeyPairToKeystoreFile(rootKeyPair, rootCert, "root-cert", KEYSTORE_FILE_PATH, "PKCS12", "meditrack");

        // Generate a new KeyPair and sign it using the Root Cert Private Key
        // by generating a CSR (Certificate Signing Request)
        X500Name issuedCertSubject = new X500Name("CN=issued-cert");
        BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertKeyPair.getPublic());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);

        // Sign the new KeyPair with the root cert Private Key
        ContentSigner csrContentSigner = csrBuilder.build(rootKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

        // Use the Signed KeyPair and CSR to generate an issued Certificate
        // Here serial number is randomly generated. In general, CAs use
        // a sequence to generate Serial number and avoid collisions
        X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(rootCertIssuer, issuedCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

        JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

        // Add Extensions
        // Use BasicConstraints to say that this Cert is not a CA
        issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        // Add Issuer cert identifier as Extension
        issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert));
        issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

        // Add intended key usage extension if needed
        issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));

        // Add DNS name is cert is to used for SSL
        issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[] {
                new GeneralName(GeneralName.dNSName, "mydomain.local"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")
        }));

        X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
        X509Certificate issuedCert  = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);

        // Verify the issued cert signature against the root (issuer) cert
        issuedCert.verify(rootCert.getPublicKey(), BC_PROVIDER);

        writeCertToFileBase64Encoded(issuedCert, KEYSTORE_FILE_PATH);
        exportKeyPairToKeystoreFile(issuedCertKeyPair, issuedCert, "issued-cert" + username, KEYSTORE_FILE_PATH, "PKCS12", "meditrack");

    }

    static void exportKeyPairToKeystoreFile(KeyPair keyPair, X509Certificate certificate, String alias, String fileName, String storeType, String storePass) throws Exception {
        KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);
    
        // Load the existing keystore, if any
        try (FileInputStream keyStoreInputStream = new FileInputStream(fileName)) {
            sslKeyStore.load(keyStoreInputStream, storePass.toCharArray());
        } catch (Exception e) {
            // If the keystore does not exist yet, create a new one
            sslKeyStore.load(null, null);
        }
    
        // Check if the alias already exists in the keystore
        Enumeration<String> aliases = sslKeyStore.aliases();
        while (aliases.hasMoreElements()) {
            if (aliases.nextElement().equals(alias)) {
                // Alias already exists, do nothing and return
                return;
            }
        }
    
        // Add the new key pair to the keystore
        sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(), null, new Certificate[]{certificate});
    
        // Save the updated keystore
        try (FileOutputStream keyStoreOs = new FileOutputStream(fileName)) {
            sslKeyStore.store(keyStoreOs, storePass.toCharArray());
        }
    }

    static void writeCertToFileBase64Encoded(X509Certificate certificate, String fileName) throws Exception {
        try (FileOutputStream certificateOut = new FileOutputStream(fileName, true)) {
            certificateOut.write("-----BEGIN CERTIFICATE-----".getBytes());
            certificateOut.write(Base64.encode(certificate.getEncoded()));
            certificateOut.write("-----END CERTIFICATE-----".getBytes());
        }
    }

    public static KeyPair readKeyPairFromKeystore(String username, String keystorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BC_PROVIDER);
        FileInputStream keyStoreInputStream = new FileInputStream(KEYSTORE_FILE_PATH);

        keyStore.load(keyStoreInputStream, keystorePassword.toCharArray());

        Key key = keyStore.getKey("issued-cert" + username, keystorePassword.toCharArray());
        if (key instanceof PrivateKey) {
            Certificate cert = keyStore.getCertificate("issued-cert" + username);
            PublicKey publicKey = cert.getPublicKey();

            return new KeyPair(publicKey, (PrivateKey) key);
        }

        throw new RuntimeException("Failed to read KeyPair from keystore for: " + username);
    }
}

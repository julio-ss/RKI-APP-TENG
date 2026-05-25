package br.zire.rkiapp.security;

import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.*;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import br.zire.rkiapp.util.Logger;

public class RklCertificateVerifier {

    /*
     SHA256 fingerprint da Root CA autorizada.
     Deve ser configurado com o fingerprint real da CA do fabricante.
    */
    private static final String ROOT_CA_SHA256 =
            "PUT_ROOT_CA_SHA256_FINGERPRINT_HERE";

    /**
     * Verifica cadeia de certificados do fluxo RKL
     *
     * POS Certificate
     *   ↓
     * Intermediate CA
     *   ↓
     * Root CA
     */
    public static boolean verifyCertificate(
            String posCertificateB64,
            String intermediateCaCertB64,
            String rootCaCertB64
    ) {

        try {

            Logger.section("RKL CERTIFICATE VALIDATION");

            //----------------------------------------
            // PARSE CERTIFICADOS
            //----------------------------------------

            X509Certificate posCert = parseCertificate(posCertificateB64);
            X509Certificate intermediateCert = parseCertificate(intermediateCaCertB64);
            X509Certificate rootCert = parseCertificate(rootCaCertB64);

            if (posCert == null || intermediateCert == null || rootCert == null) {

                Logger.error("Falha ao converter certificados");
                return false;
            }

            //----------------------------------------
            // VALIDAR PERÍODO DE VALIDADE
            //----------------------------------------

            posCert.checkValidity();
            intermediateCert.checkValidity();
            rootCert.checkValidity();

            Logger.info("✓ Certificados dentro do período de validade");

            //----------------------------------------
            // VALIDAR ASSINATURA CRIPTOGRÁFICA
            //----------------------------------------

            PublicKey intermediateKey = intermediateCert.getPublicKey();
            PublicKey rootKey = rootCert.getPublicKey();

            posCert.verify(intermediateKey);
            intermediateCert.verify(rootKey);

            Logger.info("✓ Assinaturas dos certificados válidas");

            //----------------------------------------
            // VALIDAR CADEIA PKIX
            //----------------------------------------

            List<X509Certificate> certChain =
                    Arrays.asList(posCert, intermediateCert);

            CertificateFactory certFactory =
                    CertificateFactory.getInstance("X.509");

            CertPath certPath =
                    certFactory.generateCertPath(certChain);

            TrustAnchor trustAnchor =
                    new TrustAnchor(rootCert, null);

            PKIXParameters params =
                    new PKIXParameters(Collections.singleton(trustAnchor));

            params.setRevocationEnabled(false);

            CertPathValidator validator =
                    CertPathValidator.getInstance("PKIX");

            validator.validate(certPath, params);

            Logger.info("✓ PKIX validation OK");

            //----------------------------------------
            // VALIDAR FINGERPRINT DA ROOT
            //----------------------------------------

            String rootFingerprint =
                    sha256Fingerprint(rootCert);

            Logger.info("Root CA SHA256: " + rootFingerprint);

            if (!ROOT_CA_SHA256.equalsIgnoreCase(rootFingerprint)) {

                Logger.error("Root CA fingerprint inválido");
                return false;
            }

            Logger.info("✓ Root CA fingerprint válido");

            //----------------------------------------
            // VALIDAR RELAÇÃO ISSUER / SUBJECT
            //----------------------------------------

            String issuer = posCert.getIssuerX500Principal().getName();
            String subject = intermediateCert.getSubjectX500Principal().getName();

            if (!issuer.equalsIgnoreCase(subject)) {

                Logger.error("Issuer mismatch entre POS e Intermediate");
                return false;
            }

            Logger.info("✓ Cadeia de certificados consistente");

            return true;

        }
        catch (Exception e) {

            Logger.error("Erro na validação da cadeia de certificados");
            Logger.error(e.getMessage());
            return false;
        }
    }

    //----------------------------------------
    // CONVERTER BASE64 → X509
    //----------------------------------------

    private static X509Certificate parseCertificate(String certBase64) {

        try {

            certBase64 = certBase64
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replace("\n", "")
                    .replace("\r", "");

            byte[] certBytes =
                    Base64.decode(certBase64, Base64.NO_WRAP);

            CertificateFactory factory =
                    CertificateFactory.getInstance("X.509");

            return (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(certBytes)
            );

        }
        catch (Exception e) {

            Logger.error("Erro ao converter certificado X509");
            return null;
        }
    }

    //----------------------------------------
    // GERAR FINGERPRINT SHA256
    //----------------------------------------

    private static String sha256Fingerprint(X509Certificate cert) throws Exception {

        MessageDigest digest =
                MessageDigest.getInstance("SHA-256");

        byte[] hash =
                digest.digest(cert.getEncoded());

        StringBuilder hex = new StringBuilder();

        for (byte b : hash) {

            String s = Integer.toHexString(0xff & b);

            if (s.length() == 1)
                hex.append('0');

            hex.append(s);
        }

        return hex.toString().toUpperCase();
    }
}
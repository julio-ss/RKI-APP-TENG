package br.zire.rkiapp.security;

import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import br.zire.rkiapp.util.Logger;

public class RklCertificateParser {

    /**
     * Converte PEM completo (com BEGIN/END) para Base64
     */
    public static String pemToBase64(String pem) {

        try {

            if (pem == null || pem.isEmpty()) {
                Logger.error("PEM inválido");
                return null;
            }

            byte[] pemBytes = pem.getBytes(StandardCharsets.UTF_8);

            return Base64.encodeToString(pemBytes, Base64.NO_WRAP);

        } catch (Exception e) {

            Logger.error("Erro ao converter PEM → Base64");
            return null;
        }
    }

    /**
     * Extrai a PublicKey de um certificado PEM X509
     *  ESSENCIAL para criptografia da KBPK
     */
    public static PublicKey extractPublicKey(String pemCertificate) {

        try {

            if (pemCertificate == null || pemCertificate.isEmpty()) {
                Logger.error("Certificado PEM inválido");
                return null;
            }

            //--------------------------------
            // Remove header/footer
            //--------------------------------
            String cleanPem = pemCertificate
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");

            //--------------------------------
            // Base64 decode
            //--------------------------------
            byte[] certBytes = Base64.decode(cleanPem, Base64.DEFAULT);

            //--------------------------------
            // X509 parsing
            //--------------------------------
            CertificateFactory factory =
                    CertificateFactory.getInstance("X.509");

            ByteArrayInputStream inputStream =
                    new ByteArrayInputStream(certBytes);

            X509Certificate certificate =
                    (X509Certificate) factory.generateCertificate(inputStream);

            PublicKey publicKey = certificate.getPublicKey();

            Logger.success("✓ PublicKey extraída do certificado");

            return publicKey;

        } catch (Exception e) {

            Logger.error("Erro ao extrair PublicKey do certificado");
            e.printStackTrace();
            return null;
        }
    }
}
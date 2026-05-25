package br.zire.rkiapp.crypto;

import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import br.zire.rkiapp.util.Logger;

public class RsaKeyInspector {

    /**
     * Extrai o modulus (n) da chave pública de um certificado PEM
     */
    public static String extractModulusFromPem(String certPem) {

        try {

            //--------------------------------
            // REMOVER HEADER/FOOTER
            //--------------------------------
            String cleanPem = certPem
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");

            //--------------------------------
            // BASE64 → BYTE[]
            //--------------------------------
            byte[] certBytes = Base64.decode(cleanPem, Base64.DEFAULT);

            //--------------------------------
            // PARSE CERTIFICADO
            //--------------------------------
            CertificateFactory factory =
                    CertificateFactory.getInstance("X.509");

            X509Certificate certificate =
                    (X509Certificate) factory.generateCertificate(
                            new ByteArrayInputStream(certBytes)
                    );

            //--------------------------------
            // EXTRAIR PUBLIC KEY
            //--------------------------------
            PublicKey publicKey = certificate.getPublicKey();

            if (!(publicKey instanceof RSAPublicKey)) {

                Logger.error("Chave não é RSA");
                return null;
            }

            RSAPublicKey rsaKey = (RSAPublicKey) publicKey;

            //--------------------------------
            // MODULUS
            //--------------------------------
            BigInteger modulus = rsaKey.getModulus();

            String modulusHex = modulus.toString(16).toUpperCase();

            //--------------------------------
            // LOGS TÉCNICOS
            //--------------------------------
            Logger.info("RSA Key Size: " + modulus.bitLength());
            Logger.info("Modulus HEX length: " + modulusHex.length());

            return modulusHex;

        } catch (Exception e) {

            Logger.error("Erro ao extrair modulus");
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Extrai diretamente do PublicKey já carregado
     */
    public static String extractModulusFromPublicKey(PublicKey publicKey) {

        try {

            if (!(publicKey instanceof RSAPublicKey)) {

                Logger.error("Chave não é RSA");
                return null;
            }

            RSAPublicKey rsaKey = (RSAPublicKey) publicKey;

            BigInteger modulus = rsaKey.getModulus();

            String modulusHex = modulus.toString(16).toUpperCase();

            Logger.info("RSA Key Size: " + modulus.bitLength());
            Logger.info("Modulus HEX length: " + modulusHex.length());

            return modulusHex;

        } catch (Exception e) {

            Logger.error("Erro ao extrair modulus da PublicKey");
            e.printStackTrace();
            return null;
        }
    }
}
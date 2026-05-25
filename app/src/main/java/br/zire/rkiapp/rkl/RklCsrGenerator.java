package br.zire.rkiapp.rkl;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.security.KeyPair;
import java.util.Base64;

import br.zire.rkiapp.util.Logger;
import br.zire.rkiapp.util.UiBridge;

public class RklCsrGenerator {

    public static String  generateCsrPem(KeyPair keyPair, String usn) {

        try {

            //------------------------------------
            // AJUSTE DO USN PARA O CSR
            //------------------------------------

            // remove zeros à esquerda
            String normalizedUsn = usn.replaceFirst("^0+(?!$)", "");

            // CN precisa ter 26 caracteres
            int csrLength = 26;

            String usnReplace =
                    String.format("%" + csrLength + "s", normalizedUsn)
                            .replace(' ', '0');

            Logger.info("USN API: " + usn);
            Logger.info("USN utilizado no CSR (CN): " + usnReplace);

            //------------------------------------
            // SUBJECT
            //------------------------------------

            String name = "CN=" + usn +
                    ",O=Tectoy-Factory" +
                    ",L=Cotia" +
                    ",ST=Sao Paulo" +
                    ",C=BR";

            X500Name subject = new X500Name(name);

            //------------------------------------
            // CONTENT SIGNER
            //------------------------------------

            ContentSigner signer =
                    new JcaContentSignerBuilder("SHA256withRSA")
                            .build(keyPair.getPrivate());

            //------------------------------------
            // CSR BUILDER
            //------------------------------------

            PKCS10CertificationRequestBuilder builder =
                    new JcaPKCS10CertificationRequestBuilder(
                            subject,
                            keyPair.getPublic()
                    );

            PKCS10CertificationRequest csr =
                    builder.build(signer);

            //------------------------------------
            // DER
            //------------------------------------

            byte[] der = csr.getEncoded();

            //------------------------------------
            // BASE64 DER
            //------------------------------------

            String base64Der =
                    Base64.getEncoder().encodeToString(der);

            //------------------------------------
            // CONSTRUIR PEM
            //------------------------------------

            String pem =
                    "-----BEGIN CERTIFICATE REQUEST-----\n" +
                            base64Der +
                            "\n-----END CERTIFICATE REQUEST-----";

            Logger.info("CSR PEM:");
            Logger.info(pem);

            //------------------------------------
            // BASE64 DO PEM
            //------------------------------------

            String finalCsr =
                    Base64.getEncoder()
                            .encodeToString(pem.getBytes());

            UiBridge.setText("status", "Informações criptóricas geradas.");
            Logger.info("CSR FINAL BASE64 length: " + finalCsr.length());

            return finalCsr;

        }
        catch (Exception e) {

            UiBridge.setText("status", "Falha ao receber resposta.");
            Logger.error("Erro ao gerar CSR");
            e.printStackTrace();
            return null;

        }
    }
}

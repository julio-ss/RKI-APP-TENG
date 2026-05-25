package br.zire.rkiapp.rkl;

import android.util.Base64;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.UUID;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.util.Logger;
import br.zire.rkiapp.util.UiBridge;

public class RklCertificateManager {

    private final RklHttpClient httpClient;

    private static final String CONFIG_NAME = "TecToy-Factory";

    private static final String ENDPOINT =
            "http://200.160.162.200:56488/v1/rkl/cert-chain";

    public RklCertificateManager(RklHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public void requestCertificateChain() {

        try {

            UiBridge.setText("status", "Verificando certificados.");
            Logger.section("CADEIA DE CERTIFICADOS RKL");

            Thread.sleep(1500);

            Logger.info("• Preparando requisição de certificados");

            //--------------------------------
            // GERAR TRANSACTION ID
            //--------------------------------

            String transactionId = RklEphemeralCertificateManager.generateTransactionId();

            Logger.info("• TransactionId gerado: " + transactionId);

            //--------------------------------
            // PAYLOAD
            //--------------------------------

            JSONObject payload = new JSONObject();

            payload.put("transactionId", RklEphemeralCertificateManager.generateTransactionId());
            payload.put("configName", CONFIG_NAME);
            payload.put("usn", MainActivity.USN);

            Logger.info("• Payload preparado");

            //--------------------------------
            // REQUEST
            //--------------------------------

            String response = httpClient.post(
                    MainActivity.context.getString(R.string.cert_chain_endpoint),
                    payload.toString()
            );

            if (response == null || response.isEmpty()) {

                UiBridge.setText("status", "Falha ao receber resposta.");
                Logger.error("Resposta vazia do servidor");

                return;
            }

            Logger.info("✓ Resposta recebida do servidor");

            //--------------------------------
            // SALVAR CERTIFICADOS
            //--------------------------------

            JSONObject json = new JSONObject(response);

            RklSessionContext.rootCa =
                    json.optString("rootCert");

            RklSessionContext.intermediateCa =
                    json.optString("intermediateCert");

            UiBridge.setText("status", "Certificados recebidos.");
            Logger.info("RESPONSE: " + response);
            Logger.success("✓ Cadeia de certificados armazenada");

        }
        catch (Exception e) {

            UiBridge.setText("status", "Falha ao receber resposta.");
            Logger.error("Erro ao solicitar cadeia de certificados");

            e.printStackTrace();
        }

    }


    /**
     * Normaliza CSR removendo headers PEM
     */
    public static String normalizeCsr(String csrPem) {

        if (csrPem == null) {
            return null;
        }

        return csrPem
                .replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                .replace("-----END CERTIFICATE REQUEST-----", "")
                .replace("\n", "")
                .replace("\r", "")
                .trim();
    }

}
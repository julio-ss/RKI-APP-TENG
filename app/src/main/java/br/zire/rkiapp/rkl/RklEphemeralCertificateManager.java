package br.zire.rkiapp.rkl;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import org.json.JSONObject;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.security.RklCertificateParser;
import br.zire.rkiapp.security.RklCertificateStore;
import br.zire.rkiapp.util.Logger;
import br.zire.rkiapp.util.UiBridge;

public class RklEphemeralCertificateManager {

    private final RklHttpClient httpClient;

    private static final String ENDPOINT =
            "http://200.160.162.200:56488/v1/rkl/cert-ephemere";

    public RklEphemeralCertificateManager(RklHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public static String generateTransactionId() {
        return java.util.UUID.randomUUID().toString();
    }

    public boolean requestEphemeralCertificate(Context context) {

        try {

            Logger.section("CERTIFICADO EFÊMERO");

            //------------------------------------
            // VALIDA SESSION
            //------------------------------------

            if (RklSessionContext.transactionId == null) {

                Logger.error("transactionId da sessão é NULL");
                return false;
            }

            //------------------------------------
            // MONTAR PAYLOAD
            //------------------------------------

            JSONObject body = new JSONObject();

            body.put("transactionId", generateTransactionId());
            body.put("configName", "TecToy-Factory");
            body.put("usn", MainActivity.USN);

            Log.i("USN Ephemere", "USN Ephemere: " + MainActivity.USN);

            String requestBody = body.toString();

            //------------------------------------
            // LOG REQUEST
            //------------------------------------

            Logger.section("HTTP REQUEST");

            Logger.info("HTTP METHOD: POST");
            Logger.info("URL: " + MainActivity.context.getString(R.string.ephemer_cert_endpoint));
            Logger.info("TransactionId: " + RklSessionContext.transactionId);
            Logger.info("Payload Length: " + requestBody.length());
            Logger.info("REQUEST BODY JSON:");
            Logger.info(requestBody);

            //------------------------------------
            // REQUEST API
            //------------------------------------

            String response = httpClient.post(MainActivity.context.getString(R.string.ephemer_cert_endpoint), requestBody);

            if (response == null || response.isEmpty()) {

                UiBridge.setText("status", "Falha ao receber resposta.");
                Logger.error("Resposta vazia do servidor");
                return false;
            }

            //------------------------------------
            // LOG RESPONSE
            //------------------------------------

            Logger.section("HTTP RESPONSE");

            Logger.info("Response Length: " + response.length());
            Logger.info(response);

            JSONObject json = new JSONObject(response);

            if (!json.has("issuedCertificate")) {

                UiBridge.setText("status", "Falha ao receber resposta.");
                Logger.error("Certificado efêmero não encontrado");
                return false;
            }

            String cert = json.getString("issuedCertificate");

            if (cert == null || cert.isEmpty()) {

                UiBridge.setText("status", "Falha ao receber resposta.");
                Logger.error("Certificado efêmero vazio");
                return false;
            }

            //------------------------------------
            // NORMALIZA CERTIFICADO
            //------------------------------------

            cert = normalizeToPemIfNeeded(cert);

            //------------------------------------
            // LOG CERT
            //------------------------------------

            UiBridge.setText("status", "Certificado validado.");
            Logger.section("CERTIFICADO EFÊMERO RECEBIDO");
            UiBridge.setText("status", "Certificado de autenticação recebido.");

            Logger.info("Certificate Length: " + cert.length());
            Logger.info(cert);

            //------------------------------------
            // SALVAR EM DISCO
            //------------------------------------

            RklCertificateStore.save(
                    context,
                    cert,
                    RklCertificateStore.EPHEMERAL_CERT
            );

            //------------------------------------
            // SALVAR EM SESSÃO
            //------------------------------------

            RklSessionContext.ephemeralCertificatePem = cert;

            //------------------------------------
            // EXTRAIR PUBLIC KEY
            //------------------------------------

            RklSessionContext.ephemeralPublicKey =
                    RklCertificateParser.extractPublicKey(cert);

            if (RklSessionContext.ephemeralPublicKey == null) {

                UiBridge.setText("status", "Falha ao receber resposta.");
                Logger.error("Falha ao extrair chave pública efêmera");
                return false;
            }

            UiBridge.setText("status", "Certificado extraído.");
            Logger.info("✓ Chave pública efêmera extraída com sucesso");

            return true;

        } catch (Exception e) {

            UiBridge.setText("status", "Falha ao receber resposta.");
            Logger.error("Falha ao obter certificado efêmero");
            e.printStackTrace();
            return false;
        }
    }

    //------------------------------------
    // NORMALIZA BASE64 → PEM
    //------------------------------------

    private static String normalizeToPemIfNeeded(String input) {

        try {

            if (input == null) return null;

            // já está correto
            if (input.contains("BEGIN CERTIFICATE")) {
                return input;
            }

            // veio em Base64 DER
            if (input.startsWith("LS0t")) {

                Logger.warning("Certificado Base64 → PEM");

                byte[] decoded = Base64.decode(input, Base64.NO_WRAP);

                String base64 = Base64.encodeToString(decoded, Base64.NO_WRAP);

                return "-----BEGIN CERTIFICATE-----\n"
                        + base64
                        + "\n-----END CERTIFICATE-----";
            }

            return input;

        } catch (Exception e) {

            Logger.error("Erro ao normalizar certificado");
            return input;
        }
    }

    private String normalizeToPemIfNeeded1(String cert) {

        try {

            if (cert.contains("BEGIN CERTIFICATE")) {
                return cert;
            }

            Logger.warning("Certificado efêmero estava em Base64 → convertendo para PEM");

            byte[] decoded = Base64.decode(cert, Base64.NO_WRAP);

            return new String(decoded);

        } catch (Exception e) {

            Logger.error("Erro ao normalizar certificado efêmero");
            e.printStackTrace();

            return cert;
        }
    }
}
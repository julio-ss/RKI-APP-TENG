package br.zire.rkiapp.rkl;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.security.RklCertificateParser;
import br.zire.rkiapp.security.RklCertificateStore;
import br.zire.rkiapp.util.Logger;
import br.zire.rkiapp.util.UiBridge;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Base64;

public class RklIssuePosCertificateManager {

    private final RklHttpClient httpClient;

    private static final String CONFIG_NAME = "TecToy-Factory";
    private static final String SLOT_HSM_B64 = "MA==";
    private static final String TOKEN_HSM_B64 = "QVMxMjM=";

    public RklIssuePosCertificateManager(RklHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public void requestCertificateIssue() {

        try {

            Logger.section("CERTIFICATE ISSUE");

            //------------------------------------
            // REUTILIZA SE EXISTIR
            //------------------------------------

            String savedCert = RklCertificateStore.load(
                    MainActivity.context,
                    RklCertificateStore.POS_CERT
            );

            if (savedCert != null && !savedCert.isEmpty()) {

                Logger.success("✓ Reutilizando certificado salvo");

                RklSessionContext.posCertificatePem = savedCert;

                PublicKey pk =
                        RklCertificateParser.extractPublicKey(savedCert);

                RklSessionContext.ephemeralPublicKey = pk;

                return;
            }

            //------------------------------------
            // VALIDA CSR
            //------------------------------------

            if (RklSessionContext.csr == null) {
                Logger.error("CSR não encontrado na sessão");
                return;
            }

            //------------------------------------
            // NORMALIZA CSR
            //------------------------------------

            String csrBase64 =
                    RklCertificateManager.normalizeCsr(
                            RklSessionContext.csr
                    );

            Logger.info("CSR BASE64 LENGTH: " + csrBase64.length());

            //------------------------------------
            // HASH CSR
            //------------------------------------

            Logger.info("CSR SHA256: " + sha256(csrBase64));

            //------------------------------------
            // PAYLOAD
            //------------------------------------

            JSONObject payload = new JSONObject();

            payload.put("transactionId", RklEphemeralCertificateManager.generateTransactionId());
            payload.put("configName", CONFIG_NAME);
            payload.put("usn", MainActivity.USN);
            payload.put("csr", csrBase64);
            payload.put("slotHsmB64", SLOT_HSM_B64);
            payload.put("tokenHsmB64", TOKEN_HSM_B64);

            String response = httpClient.post(MainActivity.context.getString(R.string.cert_issue_endpoint), payload.toString());

            Logger.info("Resposta bruta do servidor:");
            Logger.info(response);

            if (response == null || response.isEmpty()) {
                Logger.warning("Servidor retornou vazio");
                return;
            }

            //------------------------------------
            // PARSE
            //------------------------------------

            JSONObject json = new JSONObject(response);

            String issuedCertificate = json.optString("issuedCertificate");

            if (issuedCertificate == null || issuedCertificate.isEmpty()) {
                Logger.error("Certificado POS não recebido");
                return;
            }

            UiBridge.setText("status", "Certificado de autenticação recebido.");
            Logger.success("✓ Certificado POS recebido");

            //------------------------------------
            // NORMALIZA PEM
            //------------------------------------

            String normalizedCert = normalizeToPemIfNeeded(issuedCertificate);

            //------------------------------------
            // SALVA SESSÃO
            //------------------------------------

            RklSessionContext.posCertificatePem = normalizedCert;

            //------------------------------------
            // EXTRAÇÃO
            //------------------------------------

            PublicKey publicKey =
                    RklCertificateParser.extractPublicKey(normalizedCert);

            if (publicKey == null) {
                Logger.error("Falha ao extrair public key");
                return;
            }

            RklSessionContext.ephemeralPublicKey = publicKey;

            Logger.success("✓ Public key do POS armazenada na sessão");

            //------------------------------------
            // SALVA EM DISCO
            //------------------------------------

            RklCertificateStore.save(
                    MainActivity.context,
                    normalizedCert,
                    RklCertificateStore.POS_CERT
            );

            inspectCertificate(normalizedCert);

        } catch (Exception e) {

            Logger.error("Erro no cert-issue");
            e.printStackTrace();
        }
    }

    private String normalizeToPemIfNeeded(String cert) {

        try {

            if (cert.contains("BEGIN CERTIFICATE")) {
                return cert;
            }

            Logger.warning("Convertendo Base64 → PEM");

            byte[] decoded = Base64.getDecoder().decode(cert);

            return new String(decoded);

        } catch (Exception e) {
            return cert;
        }
    }

    private String sha256(String data) throws Exception {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] hash =
                digest.digest(data.getBytes(StandardCharsets.UTF_8));

        StringBuilder hex = new StringBuilder();

        for (byte b : hash) {
            hex.append(String.format("%02x", b));
        }

        return hex.toString();
    }

    public static void inspectCertificate(String cert) {
        Logger.info("====================================");
        Logger.info("INSPEÇÃO DO CERTIFICADO POS");
        Logger.info("====================================");
    }
}
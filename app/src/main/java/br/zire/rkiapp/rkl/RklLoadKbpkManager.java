package br.zire.rkiapp.rkl;

import static br.zire.rkiapp.util.HexUtil.hexToBytes;

import android.util.Base64;

import org.bouncycastle.crypto.io.MacInputStream;
import org.json.JSONObject;

import java.security.PublicKey;
import java.security.Signature;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.crypto.KeyInjectionManager;
import br.zire.rkiapp.crypto.RsaCryptoManager;
import br.zire.rkiapp.crypto.RsaKeyInspector;
import br.zire.rkiapp.crypto.Tr31Parser;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.security.RklCertificateParser;
import br.zire.rkiapp.security.RklCertificateStore;
import br.zire.rkiapp.util.Logger;
import br.zire.rkiapp.util.UiBridge;

public class RklLoadKbpkManager {

    private final RklHttpClient httpClient;

    private static final String CONFIG_NAME = "TecToy-Factory";

    private static final String SLOT_HSM_B64 = "MA==";
    private static final String TOKEN_HSM_B64 = "QVMxMjM=";

    public RklLoadKbpkManager(RklHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public boolean loadKbpk() {

        try {

            Logger.section("LOAD KBPK");
            UiBridge.setText("status", "Carregando criptografia...");

            String certBase64 =
                    RklCertificateParser.pemToBase64(
                            RklSessionContext.posCertificatePem
                    );

            String kbpkHex;

            if (RklSessionContext.kbpkHex == null) {

//                kbpkHex = generateKbpkHex();
                kbpkHex = "9B9BECEC8516B583851FC462D013A252F8CE983E7CD349071CFD681A7FE6A49D";

                RklSessionContext.kbpkHex = kbpkHex;
                RklSessionContext.kbpkPlain = hexToBytes(kbpkHex);

                Logger.info("KBPK GERADA");

            } else {

                kbpkHex = RklSessionContext.kbpkHex;
                Logger.info("KBPK REUTILIZADA");
            }

            PublicKey pubKey =
                    RklCertificateStore.loadEphemeralPublicKey(MainActivity.context);

            Logger.info("PublicKey modulus: " +
                    RsaKeyInspector.extractModulusFromPublicKey(pubKey));

            String kbpkB64 =
                    RsaCryptoManager.encryptKbpk(kbpkHex, pubKey);

            String sign = generateSignature(kbpkB64);

            String payload =
                    "{"
                            + "\"transactionId\":\""
                            + RklEphemeralCertificateManager.generateTransactionId()
                            + "\","
                            + "\"configName\":\"" + CONFIG_NAME + "\","
                            + "\"usn\":\"" + MainActivity.USN + "\","
                            + "\"certX509\":\"" + certBase64 + "\","
                            + "\"kbpk\":\"" + kbpkB64 + "\","
                            + "\"sign\":\"" + sign + "\","
                            + "\"slotHsmB64\":\"" + SLOT_HSM_B64 + "\","
                            + "\"tokenHsmB64\":\"" + TOKEN_HSM_B64 + "\""
                            + "}";

            String response = httpClient.post(MainActivity.context.getString(R.string.load_kbpk_endpoint), payload);

            if (response == null || response.isEmpty()) {
                Logger.error("Resposta vazia KBPK");
                return false;
            }

            Logger.info("KBPK response: " + response);

            JSONObject json = new JSONObject(response);

            String tr31 = json.optString("tr31block");
            String kcv = json.optString("kcv");

            if (tr31.isEmpty() || kcv.isEmpty()) {
                Logger.error("TR31/KCV inválido");
                return false;
            }

            Tr31Parser.Tr31Data tr31Data = Tr31Parser.parse(tr31);

            if (!tr31Data.isValid) {
                Logger.error("TR31 inválido");
                return false;
            }

            Logger.section("INJECT TR31 KBPK");
            Logger.info("TR31 KBPK: " + tr31);
            boolean injected = new KeyInjectionManager()
                    .injectTr31(tr31, kcv, (byte) 2);

            if (!injected) {
                Logger.error("Falha ao injetar KBPK");
                return false;
            }

            Logger.success("KBPK injetada");

            return true;

        } catch (Exception e) {

            Logger.error("Erro load-kbpk: " + e.getMessage());
            return false;
        }
    }

    private String generateSignature(String kbpkBase64) {

        try {

            byte[] data = Base64.decode(kbpkBase64, Base64.DEFAULT);

            Signature signature = Signature.getInstance("SHA256withRSA");

            signature.initSign(RklSessionContext.privateKey);
            signature.update(data);

            byte[] signBytes = signature.sign();

            return Base64.encodeToString(signBytes, Base64.NO_WRAP);

        } catch (Exception e) {

            Logger.error("Erro assinatura");
            return null;
        }
    }

    private String generateKbpkHex() {

        byte[] bytes = new byte[32];
        new java.security.SecureRandom().nextBytes(bytes);

        StringBuilder hex = new StringBuilder();

        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }

        return hex.toString();
    }
}
package br.zire.rkiapp.rkl;

import static br.zire.rkiapp.util.HexUtil.hexToBytes;

import android.util.Base64;

import org.json.JSONObject;

import java.security.PublicKey;
import java.security.Signature;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.crypto.RsaCryptoManager;
import br.zire.rkiapp.crypto.RsaKeyInspector;
import br.zire.rkiapp.crypto.Tr31Parser;
import br.zire.rkiapp.crypto.TectoyKeyInjectionManager;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.rkl.model.RklProfileKey;
import br.zire.rkiapp.security.RklCertificateParser;
import br.zire.rkiapp.security.RklCertificateStore;
import br.zire.rkiapp.util.Logger;
import br.zire.rkiapp.util.UiBridge;

public class TectoyRklLoadKbpkManager {

    //-----------------------------------------
    // CONFIG
    //-----------------------------------------

    private static final String CONFIG_NAME = "TecToy-Factory";
    private static final String SLOT_HSM_B64 = "MA==";
    private static final String TOKEN_HSM_B64 = "QVMxMjM=";

    //-----------------------------------------
    // HTTP
    //-----------------------------------------

    private final RklHttpClient httpClient;

    //-----------------------------------------
    // CONSTRUCTOR
    //-----------------------------------------

    public TectoyRklLoadKbpkManager(RklHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    //-----------------------------------------
    // LOAD KBPK
    //-----------------------------------------

    public boolean loadKbpk() {

        try {

            Logger.section("LOAD KBPK - TECTOY");
            UiBridge.setText("status", "Carregando KBPK...");

            //-----------------------------------------
            // CERTIFICATE
            //-----------------------------------------

            String certBase64 = RklCertificateParser.pemToBase64(RklSessionContext.posCertificatePem);

            //-----------------------------------------
            // KBPK
            //-----------------------------------------

            String kbpkHex;

            if (RklSessionContext.kbpkHex == null) {

                //-----------------------------------------
                // GENERATE
                //-----------------------------------------

                kbpkHex = "9B9BECEC8516B583851FC462D013A252F8CE983E7CD349071CFD681A7FE6A49D";
                RklSessionContext.kbpkHex = kbpkHex;
                RklSessionContext.kbpkPlain = hexToBytes(kbpkHex);
                Logger.success("KBPK GERADA");

            } else {

                //-----------------------------------------
                // REUSE
                //-----------------------------------------

                kbpkHex = RklSessionContext.kbpkHex;
                Logger.info("KBPK REUTILIZADA");
            }

            //-----------------------------------------
            // PUBLIC KEY
            //-----------------------------------------

            PublicKey pubKey = RklCertificateStore.loadEphemeralPublicKey(MainActivity.context);
            Logger.info("PUBLIC KEY MODULUS: " + RsaKeyInspector.extractModulusFromPublicKey(pubKey));

            //-----------------------------------------
            // ENCRYPT KBPK
            //-----------------------------------------

            String kbpkB64 = RsaCryptoManager.encryptKbpk(kbpkHex, pubKey);

            //-----------------------------------------
            // SIGNATURE
            //-----------------------------------------

            String sign = generateSignature(kbpkB64);

            //-----------------------------------------
            // PAYLOAD
            //-----------------------------------------

            JSONObject payload = new JSONObject();
            payload.put("transactionId", RklEphemeralCertificateManager.generateTransactionId());
            payload.put("configName", CONFIG_NAME);
            payload.put("usn", MainActivity.USN);
            payload.put("certX509", certBase64);
            payload.put("kbpk", kbpkB64);
            payload.put("sign", sign);
            payload.put("slotHsmB64", SLOT_HSM_B64);
            payload.put("tokenHsmB64", TOKEN_HSM_B64);

            //-----------------------------------------
            // REQUEST
            //-----------------------------------------

            String response =
                    httpClient.post(MainActivity.context.getString(
                                    R.string.load_kbpk_endpoint
                            ), payload.toString());

            //-----------------------------------------
            // VALIDATE
            //-----------------------------------------

            if (response == null
                    || response.isEmpty()) {

                Logger.error(
                        "Resposta vazia KBPK"
                );

                return false;
            }

            Logger.info(
                    "KBPK RESPONSE: "
                            + response
            );

            //-----------------------------------------
            // JSON
            //-----------------------------------------

            JSONObject json =
                    new JSONObject(response);

            String tr31 = json.optString("tr31block", "");
            String kcv = json.optString("kcv", "");

            //-----------------------------------------
            // VALIDATE
            //-----------------------------------------

            if (tr31.isEmpty()
                    || kcv.isEmpty()) {

                Logger.error(
                        "TR31/KCV inválido"
                );

                return false;
            }

            //-----------------------------------------
            // PARSE TR31
            //-----------------------------------------

            Tr31Parser.Tr31Data tr31Data =
                    Tr31Parser.parse(
                            tr31
                    );

            if (!tr31Data.isValid) {

                Logger.error(
                        "TR31 inválido"
                );

                return false;
            }

            //-----------------------------------------
            // STORE TR31 FOR LATER USE
            //-----------------------------------------

            RklSessionContext.kbpkTr31Block = tr31;
            RklSessionContext.kbpkTr31Header = tr31Data.header;
            RklSessionContext.kbpkTr31KeyBlock = tr31Data.keyBlock;

            Logger.info(
                    "KBPK TR31 Header armazenado: "
                            + tr31Data.header
            );

            Logger.info(
                    "KBPK TR31 KeyBlock armazenado (length: "
                            + tr31Data.keyBlock.length()
                            + ")"
            );

            //-----------------------------------------
            // KBPK PROFILE KEY
            //-----------------------------------------

            RklProfileKey kbpkKey =
                    new RklProfileKey();

            kbpkKey.label = "KBPK";
            kbpkKey.keyFuncId = 1;
            kbpkKey.keyTypeId = 1;
            kbpkKey.slotTargetPhy = 2;
            kbpkKey.kcv = kcv;
            kbpkKey.active = true;

            //-----------------------------------------
            // INJECT
            //-----------------------------------------

            Logger.section("INJECT TR31 KBPK - TECTOY");
            Logger.info("TR31 KBPK: " + tr31);

            boolean injected =
                    new TectoyKeyInjectionManager(MainActivity.context).injectTr31(kbpkKey, tr31);

            //-----------------------------------------
            // VALIDATE
            //-----------------------------------------

            if (!injected) {

                Logger.error(
                        "Falha ao injetar KBPK"
                );

                return false;
            }

            //-----------------------------------------
            // SUCCESS
            //-----------------------------------------

            Logger.success(
                    "KBPK INJETADA"
            );

            UiBridge.setText(
                    "status",
                    "KBPK carregada"
            );

            return true;

        } catch (Exception e) {

            Logger.error(
                    "Erro load-kbpk-tectoy: "
                            + e.getMessage()
            );

            e.printStackTrace();

            return false;
        }
    }

    //-----------------------------------------
    // SIGNATURE
    //-----------------------------------------

    private String generateSignature(
            String kbpkBase64
    ) {

        try {

            byte[] data =
                    Base64.decode(
                            kbpkBase64,
                            Base64.DEFAULT
                    );

            Signature signature =
                    Signature.getInstance(
                            "SHA256withRSA"
                    );

            signature.initSign(
                    RklSessionContext.privateKey
            );

            signature.update(data);

            byte[] signBytes =
                    signature.sign();

            return Base64.encodeToString(
                    signBytes,
                    Base64.NO_WRAP
            );

        } catch (Exception e) {

            Logger.error(
                    "Erro assinatura"
            );

            return null;
        }
    }
}

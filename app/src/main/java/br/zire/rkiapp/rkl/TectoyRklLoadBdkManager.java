package br.zire.rkiapp.rkl;

import org.json.JSONObject;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.crypto.KeyInjectionManager;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.rkl.model.RklProfileKey;
import br.zire.rkiapp.util.Logger;

public class TectoyRklLoadBdkManager {

    private static final String CONFIG_NAME = "TecToy-Factory";
    private static final String SLOT_HSM_B64 = "MA==";
    private static final String TOKEN_HSM_B64 = "QVMxMjM=";

    private final RklHttpClient httpClient;

    public TectoyRklLoadBdkManager(RklHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    //-------------------------------------
    // LOAD BDK (SEM PARÂMETRO)
    //-------------------------------------

    public boolean loadBdk() {
        return loadBdkInternal(null);
    }

    //-------------------------------------
    // LOAD BDK (COM PARÂMETRO)
    //-------------------------------------

    public boolean loadBdk(RklProfileKey bdkKey) {
        return loadBdkInternal(bdkKey);
    }

    //-------------------------------------
    // LOAD BDK (INTERNO)
    //-------------------------------------

    private boolean loadBdkInternal(RklProfileKey profileKeyParam) {

        try {

            Logger.section("LOAD BDK - TECTOY");

            //-----------------------------------------
            // USE CONTEXT OR PARAMETER
            //-----------------------------------------

            RklProfileKey bdkKey = profileKeyParam != null
                    ? profileKeyParam
                    : RklSessionContext.bdkProfileKey;

            if (bdkKey == null) {
                Logger.error("BDK profile key não carregada");
                return false;
            }

            //-----------------------------------------
            // PAYLOAD
            //-----------------------------------------

            JSONObject payload = new JSONObject();

            payload.put("transactionId",
                    RklEphemeralCertificateManager.generateTransactionId());

            payload.put("usn", MainActivity.USN);
            payload.put("configName", CONFIG_NAME);
            payload.put("identifierKeyToBeLoad", bdkKey.label);

            payload.put("deviceKeySlot",
                    String.format("%02d", bdkKey.slotTargetPhy));

            payload.put("slotHsmB64", SLOT_HSM_B64);
            payload.put("tokenHsmB64", TOKEN_HSM_B64);
            payload.put("ksi", bdkKey.ksi);

            //-----------------------------------------
            // REQUEST
            //-----------------------------------------

            Logger.info("BDK PAYLOAD: " + payload.toString());

            String response = httpClient.post(
                    MainActivity.context.getString(R.string.load_bdk_endpoint),
                    payload.toString()
            );

            if (response == null || response.isEmpty()) {
                Logger.error("Resposta vazia BDK");
                return false;
            }

            Logger.info("BDK RESPONSE: " + response);

            //-----------------------------------------
            // PARSE
            //-----------------------------------------

            JSONObject json = new JSONObject(response);
            String tr31 = json.optString("tr31block", "");
            String kcv = json.optString("kcv", "");

            if (tr31.isEmpty()) {
                Logger.error("TR31 BDK vazio");
                return false;
            }

            //-----------------------------------------
            // STORE
            //-----------------------------------------

            bdkKey.kcv = kcv;
            RklSessionContext.bdkTr31KeyBlock = tr31;
            RklSessionContext.bdkTr31kcv = kcv;

            Logger.info("TR31 BDK: " + tr31);
            Logger.info("KCV BDK: " + kcv);

            //-----------------------------------------
            // INJECT
            //-----------------------------------------

            Logger.section("INJECT TR31 BDK - TECTOY");

            KeyInjectionManager injectionManager = new KeyInjectionManager();
            boolean injected = injectionManager.injectTr31(
                    tr31,
                    kcv,
                    (byte) bdkKey.slotTargetPhy
            );

            if (!injected) {
                Logger.error("Falha injeção BDK");
                return false;
            }

            Logger.success("BDK INJETADA");

            return true;

        } catch (Exception e) {

            Logger.error("Erro load-bdk: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
}

package br.zire.rkiapp.rkl;

import org.json.JSONObject;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.crypto.KeyInjectionManager;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.rkl.model.RklProfileKey;
import br.zire.rkiapp.util.Logger;

public class TectoyRklLoadMkManager {

    private static final String CONFIG_NAME = "TecToy-Factory";
    private static final String SLOT_HSM_B64 = "MA==";
    private static final String TOKEN_HSM_B64 = "QVMxMjM=";

    private final RklHttpClient httpClient;

    public TectoyRklLoadMkManager(RklHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    //-------------------------------------
    // LOAD MK (SEM PARÂMETRO)
    //-------------------------------------

    public boolean loadMk() {
        return loadMkInternal(null);
    }

    //-------------------------------------
    // LOAD MK (COM PARÂMETRO)
    //-------------------------------------

    public boolean loadMk(RklProfileKey mkKey) {
        return loadMkInternal(mkKey);
    }

    //-------------------------------------
    // LOAD MK (INTERNO)
    //-------------------------------------

    private boolean loadMkInternal(RklProfileKey profileKeyParam) {

        try {

            Logger.section("LOAD MK - TECTOY");

            //-----------------------------------------
            // USE CONTEXT OR PARAMETER
            //-----------------------------------------

            RklProfileKey mkKey = profileKeyParam != null
                    ? profileKeyParam
                    : RklSessionContext.mkProfileKey;

            if (mkKey == null) {
                Logger.error("MK profile key não carregada");
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
            payload.put("identifierKeyToBeLoad", mkKey.label);

            payload.put("deviceKeySlot",
                    String.format("%02d", mkKey.slotTargetPhy));

            payload.put("slotHsmB64", SLOT_HSM_B64);
            payload.put("tokenHsmB64", TOKEN_HSM_B64);
            payload.put("ksi", mkKey.ksi);

            //-----------------------------------------
            // REQUEST
            //-----------------------------------------

            Logger.info("MK PAYLOAD: " + payload.toString());

            String response = httpClient.post(
                    MainActivity.context.getString(R.string.load_mk_endpoint),
                    payload.toString()
            );

            if (response == null || response.isEmpty()) {
                Logger.error("Resposta vazia MK");
                return false;
            }

            Logger.info("MK RESPONSE: " + response);

            //-----------------------------------------
            // PARSE
            //-----------------------------------------

            JSONObject json = new JSONObject(response);
            String tr31 = json.optString("tr31block", "");
            String kcv = json.optString("kcv", "");

            if (tr31.isEmpty()) {
                Logger.error("TR31 MK vazio");
                return false;
            }

            //-----------------------------------------
            // STORE
            //-----------------------------------------

            mkKey.kcv = kcv;
            RklSessionContext.mkTr31KeyBlock = tr31;
            RklSessionContext.mkTr31kcv = kcv;

            Logger.info("TR31 MK: " + tr31);
            Logger.info("KCV MK: " + kcv);

            //-----------------------------------------
            // INJECT
            //-----------------------------------------

            Logger.section("INJECT TR31 MK - TECTOY");

            KeyInjectionManager injectionManager = new KeyInjectionManager();
            boolean injected = injectionManager.injectTr31(
                    tr31,
                    kcv,
                    (byte) mkKey.slotTargetPhy
            );

            if (!injected) {
                Logger.error("Falha injeção MK");
                return false;
            }

            Logger.success("MK INJETADA");

            return true;

        } catch (Exception e) {

            Logger.error("Erro load-mk: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
}

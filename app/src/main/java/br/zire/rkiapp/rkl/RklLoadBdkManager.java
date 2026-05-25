package br.zire.rkiapp.rkl;

import com.pos.tectoy.security.PosSecurityManager;

import org.json.JSONObject;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.crypto.KeyInjectionManager;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.util.HexUtil;
import br.zire.rkiapp.util.Logger;

public class RklLoadBdkManager {

    private final RklHttpClient httpClient;
    private final PosSecurityManager securityManager;

    private static final String CONFIG_NAME = "TecToy-Factory";
    private static final String SLOT_HSM_B64 = "MA==";
    private static final String TOKEN_HSM_B64 = "QVMxMjM=";

    public RklLoadBdkManager(RklHttpClient httpClient) {
        this.httpClient = httpClient;
        this.securityManager = PosSecurityManager.getDefault();
    }

    //-----------------------------------------
    // LOAD BDK
    //-----------------------------------------

    public boolean loadBdk() {

        try {

            Logger.section("LOAD BDK - TECTOY");

            //-----------------------------------------
            // VALIDAÇÕES
            //-----------------------------------------

            if (RklSessionContext.dataKeyLabel == null
                    || RklSessionContext.dataKeyLabel.isEmpty()) {

                Logger.error("BDK profile key não carregada");
                return false;
            }

            RklSessionContext.identifierKeyToBeLoad =
                    RklSessionContext.dataKeyLabel;

            Logger.section("SESSION CONTEXT");

            Logger.info("dataKeyLabel: " + RklSessionContext.dataKeyLabel);
            Logger.info("slotTargetPhy: " + RklSessionContext.bdkProfileKey.slotTargetPhy);

            //-----------------------------------------
            // PAYLOAD DA REQUISIÇÃO
            //-----------------------------------------

            JSONObject payload = new JSONObject();

            payload.put("transactionId",
                    RklEphemeralCertificateManager.generateTransactionId());

            payload.put("usn", MainActivity.USN);
            payload.put("configName", CONFIG_NAME);
            payload.put("identifierKeyToBeLoad",
                    RklSessionContext.identifierKeyToBeLoad);

            payload.put("deviceKeySlot",
                    String.format("%02d",
                            RklSessionContext.bdkProfileKey.slotTargetPhy));

            payload.put("slotHsmB64", SLOT_HSM_B64);
            payload.put("tokenHsmB64", TOKEN_HSM_B64);

            payload.put("ksi",
                    RklSessionContext.bdkProfileKey.ksi);

            //-----------------------------------------
            // REQUISIÇÃO HTTP
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
            // PARSE RESPOSTA
            //-----------------------------------------

            JSONObject json = new JSONObject(response);

            String tr31 = json.optString("tr31block", "");
            String kcv = json.optString("kcv", "");

            if (tr31.isEmpty()) {
                Logger.error("TR31 BDK vazio");
                return false;
            }

            //-----------------------------------------
            // ARMAZENAR CONTEXTO
            //-----------------------------------------

            RklSessionContext.bdkTr31KeyBlock = tr31;
            RklSessionContext.bdkTr31kcv = kcv;

            Logger.info("TR31 BDK: " + tr31);
            Logger.info("KCV BDK: " + kcv);

            //-----------------------------------------
            // INJETAR CHAVE
            //-----------------------------------------

            Logger.section("INJECT TR31 BDK - TECTOY");

            KeyInjectionManager injectionManager = new KeyInjectionManager();
            boolean injected = injectionManager.injectTr31(
                    tr31,
                    kcv,
                    (byte) RklSessionContext.bdkProfileKey.slotTargetPhy
            );

            if (!injected) {
                Logger.error("Falha ao injetar BDK");
                return false;
            }

            Logger.success("BDK INJETADA COM SUCESSO");

            return true;

        } catch (Exception e) {

            Logger.error("Erro load-bdk: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    //-----------------------------------------
    // OBTER VALOR PADRÃO
    //-----------------------------------------

    public boolean loadBdk(Object profileKey) {
        // Sobrecarga para compatibilidade
        return loadBdk();
    }
}

package br.zire.rkiapp.rkl;

import com.pos.tectoy.security.PosSecurityManager;

import org.json.JSONObject;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.crypto.KeyInjectionManager;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.util.HexUtil;
import br.zire.rkiapp.util.Logger;

public class RklLoadMkManager {

    private final RklHttpClient httpClient;
    private final PosSecurityManager securityManager;

    private static final String CONFIG_NAME = "TecToy-Factory";
    private static final String SLOT_HSM_B64 = "MA==";
    private static final String TOKEN_HSM_B64 = "QVMxMjM=";

    public RklLoadMkManager(RklHttpClient httpClient) {
        this.httpClient = httpClient;
        this.securityManager = PosSecurityManager.getDefault();
    }

    //-----------------------------------------
    // LOAD MK
    //-----------------------------------------

    public boolean loadMk() {

        try {

            Logger.section("LOAD MK - TECTOY");

            //-----------------------------------------
            // VALIDAÇÕES
            //-----------------------------------------

            if (RklSessionContext.mkProfileKey == null) {
                Logger.error("MK profile key não carregada");
                return false;
            }

            RklSessionContext.identifierKeyToBeLoad =
                    RklSessionContext.mkProfileKey.label;

            if (RklSessionContext.identifierKeyToBeLoad == null) {
                Logger.error("identifierKeyToBeLoad não definido");
                return false;
            }

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

            payload.put("headerTR31", "");

            payload.put("ksi",
                    RklSessionContext.mkProfileKey.ksi);

            payload.put("deviceKeySlot",
                    String.format("%02d",
                            RklSessionContext.mkProfileKey.slotTargetPhy));

            payload.put("slotHsmB64", SLOT_HSM_B64);
            payload.put("tokenHsmB64", TOKEN_HSM_B64);

            //-----------------------------------------
            // REQUISIÇÃO HTTP
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
            // PARSE RESPOSTA
            //-----------------------------------------

            JSONObject json = new JSONObject(response);

            String tr31 = json.optString("tr31block", "");
            String kcv = json.optString("kcv", "");

            if (tr31.isEmpty()) {
                Logger.error("TR31 MK vazio");
                return false;
            }

            //-----------------------------------------
            // ARMAZENAR CONTEXTO
            //-----------------------------------------

            RklSessionContext.mkTr31KeyBlock = tr31;
            RklSessionContext.mkTr31kcv = kcv;

            Logger.info("TR31 MK: " + tr31);
            Logger.info("KCV MK: " + kcv);

            //-----------------------------------------
            // INJETAR CHAVE
            //-----------------------------------------

            Logger.section("INJECT TR31 MK - TECTOY");

            KeyInjectionManager injectionManager = new KeyInjectionManager();
            boolean injected = injectionManager.injectTr31(
                    tr31,
                    kcv,
                    (byte) RklSessionContext.mkProfileKey.slotTargetPhy
            );

            if (!injected) {
                Logger.error("Falha ao injetar MK");
                return false;
            }

            Logger.success("MK INJETADA COM SUCESSO");

            return true;

        } catch (Exception e) {

            Logger.error("Erro load-mk: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    //-----------------------------------------
    // OBTER VALOR PADRÃO
    //-----------------------------------------

    public boolean loadMk(Object profileKey) {
        // Sobrecarga para compatibilidade
        return loadMk();
    }
}

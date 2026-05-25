package br.zire.rkiapp.rkl;

import org.json.JSONObject;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.util.Logger;
import br.zire.rkiapp.util.UiBridge;

public class RklSerialNumberStatusManager {

    //--------------------------------
    // STATUS
    //--------------------------------

    public static final int STATUS_EXECUTING = 1;
    public static final int STATUS_SUCCESS = 2;
    public static final int STATUS_FAILED = 3;

    //--------------------------------
    // HTTP CLIENT
    //--------------------------------

    private final RklHttpClient httpClient;

    public RklSerialNumberStatusManager(RklHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    //--------------------------------
    // UPDATE STATUS
    //--------------------------------

    public boolean updateStatus(int status) {

        try {

            Logger.section("SERIAL NUMBER STATUS UPDATE");

            //--------------------------------
            // VALIDATION
            //--------------------------------

            if (MainActivity.SN == null || MainActivity.SN.trim().isEmpty()) {

                Logger.error("USN inválido para atualização de status");
                return false;
            }

            //--------------------------------
            // BUILD PAYLOAD
            //--------------------------------

            JSONObject payload = new JSONObject();

            payload.put("serialNumber", MainActivity.SN);
            payload.put("status", status);

            Logger.info("• Atualizando status do serial number");
            Logger.info("• Status: " + getStatusDescription(status));

            UiBridge.setText(
                    "status",
                    "Atualizando status do terminal"
            );

            //--------------------------------
            // REQUEST
            //--------------------------------

            String response = httpClient.patch(
                    MainActivity.context.getString(R.string.sn_update_endpoint),
                    payload.toString()
            );

            //--------------------------------
            // RESPONSE VALIDATION
            if (response == null || response.isEmpty()) {

                Logger.error("Resposta vazia ao atualizar status");
                return false;
            }

            Logger.success("Status atualizado com sucesso");
            Logger.info("• Response: " + response);

            return true;

        } catch (Exception e) {

            Logger.error("Erro ao atualizar status do serial number");
            Logger.error("• Exception: " + e.getMessage());

            e.printStackTrace();

            return false;
        }
    }

    //--------------------------------
    // STATUS DESCRIPTION
    //--------------------------------

    private String getStatusDescription(int status) {

        switch (status) {

            case STATUS_EXECUTING:
                return "EXECUTING";

            case STATUS_SUCCESS:
                return "KEY_LOADED_SUCCESSFULLY";

            case STATUS_FAILED:
                return "KEY_LOAD_FAILED";

            default:
                return "UNKNOWN";
        }
    }
}
package br.zire.rkiapp.rkl;

import org.json.JSONObject;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.crypto.TectoyKeyInjectionManager;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.rkl.model.RklProfileKey;
import br.zire.rkiapp.util.Logger;

public class TectoyRklLoadBdkManager {

    //-----------------------------------------
    // CONFIG
    //-----------------------------------------

    private static final String CONFIG_NAME =
            "TecToy-Factory";

    //-----------------------------------------
    // HTTP
    //-----------------------------------------

    private final RklHttpClient httpClient;

    //-----------------------------------------
    // CONSTRUCTOR
    //-----------------------------------------

    public TectoyRklLoadBdkManager(
            RklHttpClient httpClient
    ) {

        this.httpClient = httpClient;
    }

    //-----------------------------------------
    // LOAD BDK
    //-----------------------------------------

    public boolean loadBdk(
            RklProfileKey bdkKey
    ) {

        try {

            Logger.section(
                    "LOAD BDK - TECTOY"
            );

            //-----------------------------------------
            // VALIDATE
            //-----------------------------------------

            if (bdkKey == null) {

                Logger.error(
                        "BDK KEY NULL"
                );

                return false;
            }

            //-----------------------------------------
            // VALIDATE TYPE
            //-----------------------------------------

            if (!bdkKey.isBdk()) {

                Logger.error(
                        "KEY NÃO É BDK"
                );

                return false;
            }

            //-----------------------------------------
            // PAYLOAD
            //-----------------------------------------

            JSONObject payload =
                    new JSONObject();

            payload.put(
                    "transactionId",
                    RklEphemeralCertificateManager
                            .generateTransactionId()
            );

            payload.put(
                    "usn",
                    MainActivity.USN
            );

            payload.put(
                    "configName",
                    CONFIG_NAME
            );

            //-----------------------------------------
            // KEY LABEL
            //-----------------------------------------

            payload.put(
                    "identifierKeyToBeLoad",
                    bdkKey.label
            );

            //-----------------------------------------
            // SLOT
            //-----------------------------------------

            payload.put(
                    "deviceKeySlot",
                    String.format(
                            "%02d",
                            bdkKey.slotTargetPhy
                    )
            );

            //-----------------------------------------
            // HSM
            //-----------------------------------------

            payload.put(
                    "slotHsmB64",
                    bdkKey.slotHsmB64
            );

            payload.put(
                    "tokenHsmB64",
                    bdkKey.tokenHsmB64
            );

            //-----------------------------------------
            // KSN
            //-----------------------------------------

            payload.put(
                    "ksi",
                    bdkKey.ksn
            );

            //-----------------------------------------
            // REQUEST
            //-----------------------------------------

            Logger.info(
                    "BDK PAYLOAD: "
                            + payload
            );

            String response =
                    httpClient.post(
                            MainActivity.context.getString(
                                    R.string.load_bdk_endpoint
                            ),
                            payload.toString()
                    );

            //-----------------------------------------
            // VALIDATE RESPONSE
            //-----------------------------------------

            if (response == null
                    || response.isEmpty()) {

                Logger.error(
                        "Resposta vazia BDK"
                );

                return false;
            }

            Logger.info(
                    "BDK RESPONSE: "
                            + response
            );

            //-----------------------------------------
            // JSON
            //-----------------------------------------

            JSONObject json =
                    new JSONObject(response);

            String tr31 =
                    json.optString(
                            "tr31block",
                            ""
                    );

            String kcv =
                    json.optString(
                            "kcv",
                            ""
                    );

            //-----------------------------------------
            // VALIDATE
            //-----------------------------------------

            if (tr31.isEmpty()) {

                Logger.error(
                        "TR31 BDK vazio"
                );

                return false;
            }

            //-----------------------------------------
            // UPDATE KCV
            //-----------------------------------------

            bdkKey.kcv =
                    kcv;

            //-----------------------------------------
            // INJECT
            //-----------------------------------------

            Logger.section(
                    "INJECT TR31 BDK - TECTOY"
            );

            Logger.info(
                    "TR31 BDK: "
                            + tr31
            );

            Logger.info(
                    "KCV BDK: "
                            + kcv
            );

            boolean injected =
                    new TectoyKeyInjectionManager(
                            MainActivity.context
                    ).injectTr31(
                            bdkKey,
                            tr31
                    );

            //-----------------------------------------
            // VALIDATE
            //-----------------------------------------

            if (!injected) {

                Logger.error(
                        "Falha injeção BDK"
                );

                return false;
            }

            //-----------------------------------------
            // SUCCESS
            //-----------------------------------------

            Logger.success(
                    "BDK INJETADA"
            );

            return true;

        } catch (Exception e) {

            Logger.error(
                    "Erro load-bdk-tectoy: "
                            + e.getMessage()
            );

            e.printStackTrace();

            return false;
        }
    }
}

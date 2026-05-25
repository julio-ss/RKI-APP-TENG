package br.zire.rkiapp.rkl;

import org.json.JSONObject;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.crypto.TectoyKeyInjectionManager;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.rkl.model.RklProfileKey;
import br.zire.rkiapp.util.Logger;

public class TectoyRklLoadMkManager {

    //-----------------------------------------
    // CONFIG
    //-----------------------------------------

    private static final String CONFIG_NAME =
            "TecToy-Factory";

    private static final String SLOT_HSM_B64 =
            "MA==";

    private static final String TOKEN_HSM_B64 =
            "QVMxMjM=";

    //-----------------------------------------
    // HTTP
    //-----------------------------------------

    private final RklHttpClient httpClient;

    //-----------------------------------------
    // CONSTRUCTOR
    //-----------------------------------------

    public TectoyRklLoadMkManager(
            RklHttpClient httpClient
    ) {

        this.httpClient = httpClient;
    }

    //-----------------------------------------
    // LOAD MK
    //-----------------------------------------

    public boolean loadMk(
            RklProfileKey mkKey
    ) {

        try {

            Logger.section(
                    "LOAD MK - TECTOY"
            );

            //-----------------------------------------
            // VALIDATE
            //-----------------------------------------

            if (mkKey == null) {

                Logger.error(
                        "MK KEY NULL"
                );

                return false;
            }

            //-----------------------------------------
            // VALIDATE TYPE
            //-----------------------------------------

            if (!mkKey.isMk()) {

                Logger.error(
                        "KEY NÃO É MK"
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

            payload.put(
                    "identifierKeyToBeLoad",
                    mkKey.label
            );

            //-----------------------------------------
            // SLOT
            //-----------------------------------------

            payload.put(
                    "deviceKeySlot",
                    String.format(
                            "%02d",
                            mkKey.slotTargetPhy
                    )
            );

            //-----------------------------------------
            // HSM
            //-----------------------------------------

            payload.put(
                    "slotHsmB64",
                    mkKey.slotHsmB64
            );

            payload.put(
                    "tokenHsmB64",
                    mkKey.tokenHsmB64
            );

            //-----------------------------------------
            // KSN
            //-----------------------------------------

            payload.put(
                    "ksi",
                    mkKey.ksn
            );

            //-----------------------------------------
            // REQUEST
            //-----------------------------------------

            Logger.info(
                    "MK PAYLOAD: "
                            + payload
            );

            String response =
                    httpClient.post(
                            MainActivity.context.getString(
                                    R.string.load_mk_endpoint
                            ),
                            payload.toString()
                    );

            //-----------------------------------------
            // VALIDATE RESPONSE
            //-----------------------------------------

            if (response == null
                    || response.isEmpty()) {

                Logger.error(
                        "Resposta vazia MK"
                );

                return false;
            }

            Logger.info(
                    "MK RESPONSE: "
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
                        "TR31 MK vazio"
                );

                return false;
            }

            //-----------------------------------------
            // UPDATE KCV
            //-----------------------------------------

            mkKey.kcv =
                    kcv;

            //-----------------------------------------
            // INJECT
            //-----------------------------------------

            Logger.section(
                    "INJECT TR31 MK - TECTOY"
            );

            Logger.info(
                    "TR31 MK: "
                            + tr31
            );

            Logger.info(
                    "KCV MK: "
                            + kcv
            );

            boolean injected =
                    new TectoyKeyInjectionManager(
                            MainActivity.context
                    ).injectTr31(
                            mkKey,
                            tr31
                    );

            //-----------------------------------------
            // VALIDATE
            //-----------------------------------------

            if (!injected) {

                Logger.error(
                        "Falha injeção MK"
                );

                return false;
            }

            //-----------------------------------------
            // SUCCESS
            //-----------------------------------------

            Logger.success(
                    "MK INJETADA"
            );

            return true;

        } catch (Exception e) {

            Logger.error(
                    "Erro load-mk-tectoy: "
                            + e.getMessage()
            );

            e.printStackTrace();

            return false;
        }
    }
}

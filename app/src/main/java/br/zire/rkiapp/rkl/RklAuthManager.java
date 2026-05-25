package br.zire.rkiapp.rkl;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.util.Logger;
import br.zire.rkiapp.util.UiBridge;

import org.json.JSONObject;

public class RklAuthManager {

    private RklHttpClient httpClient;

    public static String AUTH_TOKEN = null;

    public RklAuthManager(RklHttpClient httpClient) {

        this.httpClient = httpClient;

    }

    public void requestToken() {

        new Thread(() -> {

            try {

                UiBridge.setText("status", "Autenticando...");
                Logger.section("AUTENTICAÇÃO TOKEN");

                Thread.sleep(1500);

                JSONObject payload = new JSONObject();

                payload.put(
                        "client_id",
                        "f0fc0ec6-0d0f-4c05-bfe5-6c1b4a918172"
                );

                payload.put(
                        "client_secret",
                        "94a34cbf-1e32-4d93-8f01-bc4f0f73e029"
                );

                String response =
                        httpClient.post(
                                MainActivity.context.getString(R.string.auth_endpoint),
                                payload.toString()
                        );

                if (response == null || response.isEmpty()) {

                    UiBridge.stopAnimation("status");
                    UiBridge.setText("status", "Falha na autenticação.");

                    Logger.error("Resposta de autenticação vazia");

                    return;

                }

                JSONObject json = new JSONObject(response);

                if (json.has("Token")) {

                    AUTH_TOKEN = json.getString("Token");

                    UiBridge.setText("status", "Token autenticado.");

                    Thread.sleep(1000);
                    Logger.success("Token recebido com sucesso");

                    if(json.has("Expires")) {

                        Logger.info("Validade do token: " +
                                json.getString("Expires"));

                    }

                } else {

                    Logger.error("Campo Token não encontrado");

                }

            }
            catch (Exception e) {

                UiBridge.setText("status", "Falha na autenticação.");
                Logger.error("Erro na autenticação");

                e.printStackTrace();

            }

        }).start();

    }

}
package br.zire.rkiapp.rkl;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.util.Logger;
import br.zire.rkiapp.util.UiBridge;

public class RklConnectivityManager {

    private RklHttpClient httpClient;

    public RklConnectivityManager(RklHttpClient httpClient) {

        this.httpClient = httpClient;

    }

    public void testServers() {

        new Thread(() -> {

            try {
                Logger.section("VALIDA CONECTIVIDADE");

                String response56488 = httpClient.get(MainActivity.context.getString(R.string.health_endpoint));

                if (response56488 != null) {

                    UiBridge.setText("log", "Conectado");
                    Logger.success("Servidor 56488 conectado");

                } else {

                    UiBridge.setText("log", "Desconectado");
                    Logger.error("Falha ao conectar servidor 56488");

                }

                Logger.info("Teste de conectividade finalizado");

            }
            catch (Exception e) {

                Logger.error("Erro de conectividade");

                e.printStackTrace();

            }

        }).start();

    }

}
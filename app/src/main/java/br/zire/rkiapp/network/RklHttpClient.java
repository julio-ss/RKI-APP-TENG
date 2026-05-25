package br.zire.rkiapp.network;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import br.zire.rkiapp.rkl.RklAuthManager;
import br.zire.rkiapp.util.Logger;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class RklHttpClient {

    private OkHttpClient client;

    public RklHttpClient() {

        client = new OkHttpClient();

    }

    /*
     * HTTP GET
     * usado para testar conectividade e swagger
     */

    public String get(String url) {

        try {

            Logger.info("HTTP GET URL: " + url);

            Request.Builder builder =
                    new Request.Builder()
                            .url(url)
                            .get();

            if (RklAuthManager.AUTH_TOKEN != null) {

                builder.addHeader(
                        "Authorization",
                        "Bearer " + RklAuthManager.AUTH_TOKEN
                );

            }

            Request request = builder.build();

            Response response = client.newCall(request).execute();

            Logger.info("HTTP STATUS: " + response.code());

            if (response.body() == null) {

                Logger.error("EMPTY RESPONSE BODY");

                return null;

            }

            String result = response.body().string();

            Logger.info("RESPONSE LENGTH: " + result.length());

            return result;

        }
        catch (Exception e) {

            Logger.error("HTTP GET ERROR: " + e.getMessage());

            return null;

        }

    }

    /*
     * HTTP POST
     * usado para auth e chamadas RKL
     */

    public String post(String url, String json) {

        try {

            Logger.info("HTTP POST URL: " + url);
            Logger.info("HTTP BODY: " + json);

            RequestBody body =
                    RequestBody.create(
                            json,
                            MediaType.parse("application/json"));

            Request.Builder builder =
                    new Request.Builder()
                            .url(url)
                            .post(body)
                            .addHeader("Content-Type", "application/json");

            if (RklAuthManager.AUTH_TOKEN != null) {

                builder.addHeader(
                        "Authorization",
                        "Bearer " + RklAuthManager.AUTH_TOKEN
                );

            }

            Request request = builder.build();

            Response response = client.newCall(request).execute();

            Logger.info("HTTP STATUS: " + response.code());

            if (response.body() == null) {

                Logger.error("EMPTY RESPONSE BODY");

                return null;

            }

            String result = response.body().string();

            Logger.info("RESPONSE LENGTH: " + result.length());

            return result;

        }
        catch (Exception e) {

            Logger.error("HTTP POST ERROR: " + e.getMessage());

            return null;

        }

    }

    public String patch(String endpoint, String jsonBody) throws Exception {

        HttpURLConnection connection = null;

        try {

            URL url = new URL(endpoint);

            connection = (HttpURLConnection) url.openConnection();

            connection.setRequestMethod("PATCH");

            connection.setRequestProperty(
                    "Content-Type",
                    "application/json"
            );

            connection.setRequestProperty(
                    "Accept",
                    "application/json"
            );

            //--------------------------------
            // AUTH HEADER
            //--------------------------------

            if (RklAuthManager.AUTH_TOKEN != null
                    && !RklAuthManager.AUTH_TOKEN.isEmpty()) {

                connection.setRequestProperty(
                        "Authorization",
                        "Bearer " + RklAuthManager.AUTH_TOKEN
                );
            }

            //--------------------------------
            // CONFIG
            //--------------------------------

            connection.setDoOutput(true);

            connection.setConnectTimeout(30000);
            connection.setReadTimeout(30000);

            //--------------------------------
            // SEND BODY
            //--------------------------------

            OutputStream os = connection.getOutputStream();

            os.write(jsonBody.getBytes("UTF-8"));

            os.flush();
            os.close();

            //--------------------------------
            // RESPONSE
            //--------------------------------

            int responseCode = connection.getResponseCode();

            Logger.info("PATCH ResponseCode: " + responseCode);

            InputStream inputStream;

            if (responseCode >= 200 && responseCode < 300) {

                inputStream = connection.getInputStream();

            } else {

                inputStream = connection.getErrorStream();
            }

            BufferedReader reader =
                    new BufferedReader(
                            new InputStreamReader(inputStream)
                    );

            StringBuilder response = new StringBuilder();

            String line;

            while ((line = reader.readLine()) != null) {

                response.append(line);
            }

            reader.close();

            return response.toString();

        } finally {

            if (connection != null) {

                connection.disconnect();
            }
        }
    }

}
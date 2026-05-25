package br.zire.rkiapp.domain;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.rkl.RklSessionContext;
import br.zire.rkiapp.util.Logger;
import br.zire.rkiapp.util.UiBridge;

public class SerialNumberDatails {

    private final RklHttpClient httpClient;

    public SerialNumberDatails(RklHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public void requestSerialNumberDetails() {

        try {

            UiBridge.setText("status", "Verificando requisção.");
            Logger.section("SERIAL NUMBER DETAILS");

            Thread.sleep(1500);

            Logger.info("• Preparando requisição do SN");

            //--------------------------------
            // GET SN INFORMATION
            //--------------------------------

            String responseSN =
                    httpClient.get(MainActivity.context.getString(R.string.sn_details_endpoint) + MainActivity.SN);


            if (responseSN != null) {
                UiBridge.setText("status", "SN validado");
                Logger.success("SN verificado com sucesso");
                Logger.info("Details: \n" + responseSN );

                getGroupId(responseSN);
                getProfileId(responseSN);


                String profilesResponse =
                        httpClient.get(MainActivity.context.getString(R.string.profiles_endpoint) +  getProfileId(responseSN));

                Logger.info("Profiles: \n" + profilesResponse );
                getKeys(profilesResponse);


            } else {
                UiBridge.setText("status", "Falha ao verificar número de série.");
                Logger.error("Falha ao verificar SN");
            }

        }
        catch (Exception e) {

            UiBridge.setText("status", "Falha ao receber resposta.");
            Logger.error("Erro ao verificar detalhes do SN");

            e.printStackTrace();
        }

    }

    private String getProfileId(String responseSN){
        Pattern pattern =
                Pattern.compile("\"ProfileId\":(\\d+)");

        Matcher matcher =
                pattern.matcher(responseSN);

        String profileId = "";

        if (matcher.find()) {
            profileId = matcher.group(1);
        }

        Logger.info("ProfileId: " + profileId);

        return profileId;
    }

    private void getGroupId(String responseSN){
        Pattern pattern =
                Pattern.compile("\"GroupId\":(\\d+)");

        Matcher matcher =
                pattern.matcher(responseSN);

        String groupId = "";

        if (matcher.find()) {
            groupId = matcher.group(1);
        }

        Logger.info("GroupId: " + groupId);
    }

    private void getKeys(String response){
        Logger.section("GET KEYS");

        Pattern pattern =
                Pattern.compile(
                        "\\{\\s*\"Keyid\":(.*?)\"errorMessage\":\"(.*?)\"\\s*\\}",
                        Pattern.DOTALL
                );

        Matcher matcher =
                pattern.matcher(response);

        int index = 1;

        Logger.info("• Encontrando chaves");
        while (matcher.find()) {

            String keyBlock =
                    matcher.group();

            Logger.section("KEY " + index);

            String keyId =
                    extractValue(
                            keyBlock,
                            "\"Keyid\"\\s*:\\s*(\\d+)"
                    );

            String label =
                    extractValue(
                            keyBlock,
                            "\"label\"\\s*:\\s*\"([^\"]+)\""
                    );

            String keyFuncId =
                    extractValue(
                            keyBlock,
                            "\"keyFuncId\"\\s*:\\s*(\\d+)"
                    );

            String keyTypeId =
                    extractValue(
                            keyBlock,
                            "\"KeyTypeId\"\\s*:\\s*(\\d+)"
                    );

            String slotTargetPhy =
                    extractValue(
                            keyBlock,
                            "\"slotTargetPhy\"\\s*:\\s*(\\d+)"
                    );

            String didBegin =
                    extractValue(
                            keyBlock,
                            "\"didBegin\"\\s*:\\s*([^,]+)"
                    );

            String didEnd =
                    extractValue(
                            keyBlock,
                            "\"didEnd\"\\s*:\\s*([^,]+)"
                    );

            String didActual =
                    extractValue(
                            keyBlock,
                            "\"didActual\"\\s*:\\s*([^,]+)"
                    );

            String dueDate =
                    extractValue(
                            keyBlock,
                            "\"dueDate\"\\s*:\\s*\"([^\"]+)\""
                    );

            String active =
                    extractValue(
                            keyBlock,
                            "\"active\"\\s*:\\s*(true|false)"
                    );

            String didOrphans =
                    extractValue(
                            keyBlock,
                            "\"didOrphans\"\\s*:\\s*([^,]+)"
                    );

            String ipekSize =
                    extractValue(
                            keyBlock,
                            "\"ipekSize\"\\s*:\\s*(\\d+)"
                    );

            String acqId =
                    extractValue(
                            keyBlock,
                            "\"acqId\"\\s*:\\s*(\\d+)"
                    );

            String ksi =
                    extractValue(
                            keyBlock,
                            "\"ksi\"\\s*:\\s*\"([^\"]+)\""
                    );

            Logger.info("KeyId: " + keyId);
            Logger.info("Label: " + label);
            Logger.info("KeyFuncId: " + keyFuncId);
            Logger.info("KeyTypeId: " + keyTypeId);
            Logger.info("SlotTargetPhy: " + slotTargetPhy);
            Logger.info("DidBegin: " + didBegin);
            Logger.info("DidEnd: " + didEnd);
            Logger.info("DidActual: " + didActual);
            Logger.info("DueDate: " + dueDate);
            Logger.info("Active: " + active);
            Logger.info("DidOrphans: " + didOrphans);
            Logger.info("IpekSize: " + ipekSize);
            Logger.info("AcqId: " + acqId);
            Logger.info("KSI: " + ksi);

            //--------------------------------
            // SESSION CONTEXT
            //--------------------------------

            if (label.contains("PIN")) {

                RklSessionContext.pinKeyLabel =
                        label;

                RklSessionContext.pinKeySlot =
                        Integer.parseInt(slotTargetPhy);

                RklSessionContext.pinKeyKsi =
                        ksi;

                Logger.success(
                        "PIN KEY carregada"
                );
            }

            if (label.contains("DADOS")) {

                RklSessionContext.dataKeyLabel =
                        label;

                RklSessionContext.dataKeySlot =
                        Integer.parseInt(slotTargetPhy);

                RklSessionContext.dataKeyKsi =
                        ksi;

                Logger.success(
                        "DATA KEY carregada"
                );
            }

            index++;
        }
    }

    private String extractValue(
            String content,
            String regex
    ){

        Pattern pattern =
                Pattern.compile(
                        regex,
                        Pattern.DOTALL
                );

        Matcher matcher =
                pattern.matcher(content);

        if (matcher.find()) {
            return matcher.group(1);
        }

        return "";
    }

}

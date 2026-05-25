package br.zire.rkiapp.rkl;

import android.graphics.Color;

import com.pax.dal.IPed;
import com.pax.dal.entity.EPedKeyType;
import com.pax.dal.entity.EPedType;
import com.pax.dal.exceptions.PedDevException;
import com.pax.neptunelite.api.NeptuneLiteUser;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.util.HexUtil;
import br.zire.rkiapp.util.Logger;

public class RklLoadMkManager {

    private final RklHttpClient httpClient;

    private static final String CONFIG_NAME = "TecToy-Factory";

    private static final String SLOT_HSM_B64 = "MA==";

    private static final String TOKEN_HSM_B64 = "QVMxMjM=";

    private static byte[] byte_test = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    IPed ped;

    public RklLoadMkManager(RklHttpClient httpClient) {

        this.httpClient = httpClient;
    }

    public boolean loadMk() {

        try {

            Logger.section("LOAD MK");

            ped = NeptuneLiteUser
                    .getInstance()
                    .getDal(MainActivity.context)
                    .getPed(EPedType.INTERNAL);

//            RklSessionContext.identifierKeyToBeLoad = "IPEK-KCV-5858CC";

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

            JSONObject payload = new JSONObject();

            payload.put("transactionId",
                    RklEphemeralCertificateManager.generateTransactionId());

            payload.put("usn", MainActivity.USN);
            payload.put("configName", CONFIG_NAME);
            payload.put("identifierKeyToBeLoad",
                    RklSessionContext.identifierKeyToBeLoad);

            payload.put("headerTR31", "");
//            payload.put("padding", "0");
//            payload.put("ksi", "");

            payload.put(
                    "ksi",
                    RklSessionContext.mkProfileKey.ksi
            );

            payload.put(
                    "deviceKeySlot",
                    String.format(
                            "%02d",
                            RklSessionContext.mkProfileKey.slotTargetPhy
                    )
            );

            payload.put("deviceKeySlot", "01");
            payload.put("slotHsmB64", SLOT_HSM_B64);
            payload.put("tokenHsmB64", TOKEN_HSM_B64);

            String response = httpClient.post(
                    MainActivity.context.getString(R.string.load_mk_endpoint),
                    payload.toString()
            );

            if (response == null || response.isEmpty()) {
                Logger.error("Resposta vazia MK");
                return false;
            }

            JSONObject json = new JSONObject(response);

            String tr31 = json.optString("tr31block");
            String kcv = json.optString("kcv");

            Logger.section("INJECT TR31 MK");
            Logger.info("TR31 MK: " + tr31);
            Logger.info("KCV MK: " + kcv);


            if (tr31.isEmpty()) {
                Logger.error("TR31 MK vazio");
                return false;
            }

            RklSessionContext.mkTr31KeyBlock = tr31;
            RklSessionContext.mkTr31kcv = kcv;

            writeMkTr31(RklSessionContext.mkProfileKey.slotTargetPhy, tr31.getBytes());

            return true;

        } catch (Exception e) {

            Logger.error("Erro load-mk: " + e.getMessage());
            return false;
        }
    }

    public static List<Byte> getIndicesComKcv(IPed ped, byte maxIndex) {
        Logger.section("GET PED KCV");

        List<Byte> indicesValidos = new ArrayList<>();

        for (byte i = 1; i < maxIndex; i++) {

            try {

                byte[] kcvBytes = ped.getKCV(
                        EPedKeyType.AES_TMK,
                        i,
                        (byte) 0,
                        byte_test
                );

                if (kcvBytes != null && kcvBytes.length > 0) {

                    String kcv = HexUtil
                            .bytesToHex(kcvBytes)
                            .substring(0, 6);

                    Logger.success("[" + i + "] KCV: " + kcv);

                    indicesValidos.add(i);

                }

            } catch (PedDevException e) {

                Logger.info("Indice " + i + " vazio ou inválido");

            } catch (Exception e) {

                Logger.error("Erro inesperado no indice "
                        + i
                        + ": "
                        + e.getMessage());

            }
        }

        return indicesValidos;
    }

    private void writeMkTr31(int index, byte[] byteMkTr31) {
        Logger.section("INJECT TR31 MK");

        try {
            ped.writeTR31Key(
                    EPedKeyType.AES_TMK.getPedkeyType(),
                    (byte) 99,
                    (byte) index,
                    byteMkTr31
            );

            Logger.success("MK TR31 injetada no índice: " + index);

        } catch (PedDevException e) {

            Logger.error("Erro ao injetar MK TR31 no índice " + index + ": " + e.getMessage());

        } catch (Exception e) {

            Logger.error("Erro inesperado no índice " + index + ": " + e.getMessage());
        }
    }
}
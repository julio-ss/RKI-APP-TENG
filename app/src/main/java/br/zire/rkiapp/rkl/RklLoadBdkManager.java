package br.zire.rkiapp.rkl;

import android.graphics.Color;

import com.pax.dal.IPed;
import com.pax.dal.entity.EPedKeyType;
import com.pax.dal.entity.EPedType;
import com.pax.dal.exceptions.PedDevException;
import com.pax.neptunelite.api.NeptuneLiteUser;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.crypto.Tr31Sanitizer;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.util.HexUtil;
import br.zire.rkiapp.util.Logger;

public class RklLoadBdkManager {

    private final RklHttpClient httpClient;

    private static final String CONFIG_NAME =
            "TecToy-Factory";

    private static final String SLOT_HSM_B64 =
            "MA==";

    private static final String TOKEN_HSM_B64 =
            "QVMxMjM=";

    IPed ped;

    public RklLoadBdkManager(RklHttpClient httpClient) {

        this.httpClient = httpClient;
    }

    public boolean loadBdk() {

        try {

            Logger.section("LOAD BDK");

            ped = NeptuneLiteUser
                    .getInstance()
                    .getDal(MainActivity.context)
                    .getPed(EPedType.INTERNAL);

//            RklSessionContext.identifierKeyToBeLoad = "IPEK-KCV-5858CC";
            RklSessionContext.identifierKeyToBeLoad =
                    RklSessionContext.pinKeyLabel;

            if (RklSessionContext.identifierKeyToBeLoad == null) {
                Logger.error("identifier inválido");
                return false;
            }

            if (RklSessionContext.dataKeyLabel == null
                    || RklSessionContext.dataKeyLabel.isEmpty()) {

                Logger.error("BDK profile key não carregada");

                return false;
            }

            RklSessionContext.identifierKeyToBeLoad =
                    RklSessionContext.dataKeyLabel;


            Logger.section("SESSION CONTEXT");

            Logger.info(
                    "dataKeyLabel: "
                            + RklSessionContext.dataKeyLabel
            );

            Logger.info(
                    "dataKeySlot: "
                            + RklSessionContext.dataKeySlot
            );

            Logger.info(
                    "dataKeyKsi: "
                            + RklSessionContext.dataKeyKsi
            );

            JSONObject payload = new JSONObject();

            payload.put("transactionId", RklEphemeralCertificateManager.generateTransactionId());
            payload.put("usn", MainActivity.USN);
            payload.put("configName", CONFIG_NAME);
            payload.put("identifierKeyToBeLoad", RklSessionContext.pinKeyLabel);
            payload.put("headerTR31", "");
            payload.put("padding", "0");
//            payload.put("ksi", "FFFFF305010000200000");
//            payload.put("deviceKeySlot", "01");
            payload.put("ksi", RklSessionContext.dataKeyKsi);
            payload.put("deviceKeySlot", String.format("%02d", RklSessionContext.dataKeySlot));
            payload.put("slotHsmB64", SLOT_HSM_B64);
            payload.put("tokenHsmB64", TOKEN_HSM_B64);

            String response = httpClient.post(
                    MainActivity.context.getString(R.string.load_bdk_endpoint),
                    payload.toString()
            );

            if (response == null || response.isEmpty()) {
                Logger.error("Resposta vazia BDK");
                return false;
            }

            JSONObject json = new JSONObject(response);

            String tr31 = json.optString("tr31block");
            String kcv = json.optString("kcv");

//            String tr31Sanitized = Tr31Sanitizer.sanitize(tr31);

//            Logger.info("TR31 BDK SANITIZADO: " + tr31Sanitized);
            Logger.info("TR31 BDK: " + tr31);
            Logger.info("KCV BDK: " + kcv);

//            validateTr31(tr31Sanitized);

            if (tr31.isEmpty()) {
                Logger.error("TR31 BDK vazio");
                return false;
            }

//            RklSessionContext.bdkTr31KeyBlock = tr31Sanitized;
            RklSessionContext.bdkTr31KeyBlock = tr31;
            RklSessionContext.bdkTr31Kcv = kcv;

//            writeBdkTr31(1, tr31Sanitized.getBytes(StandardCharsets.US_ASCII));
            byte[] byteBdkTr31 = tr31.getBytes(StandardCharsets.US_ASCII);
            writeBdkTr31(RklSessionContext.bdkProfileKey.slotTargetPhy, byteBdkTr31);

            Logger.success("BDK injetada");

            return true;

        } catch (Exception e) {

            Logger.error("Erro load-bdk: " + e.getMessage());
            return false;
        }
    }

    private void validateTr31(String tr31) {

        if (tr31 == null || tr31.isEmpty()) {
            throw new IllegalArgumentException("TR31 vazio");
        }

        if ((tr31.length() % 2) != 0) {
            throw new IllegalArgumentException(
                    "TR31 hexadecimal inválido"
            );
        }

        if (!tr31.matches("^[0-9A-F]+$")) {
            throw new IllegalArgumentException(
                    "TR31 contém caracteres inválidos"
            );
        }

        if (tr31.length() < 64) {
            throw new IllegalArgumentException(
                    "TR31 muito curto"
            );
        }

        Logger.success("TR31 validado");
    }

    private void writeBdkTr31(
            int index,
            byte[] byteBdkTr31
    ) {
        Logger.section("INJECT TR31 BDK");

        try {

            ped.writeTR31Key(
                    EPedKeyType.AES_TMK.getPedkeyType(),
                    (byte) 99,
                    (byte) index,
                    byteBdkTr31
            );

            byte[] bytes_ksn = ped.getDUKPTKsn((byte) 2);
            String auxDukp = HexUtil.bytesToHex(bytes_ksn);
            Logger.info("ksn: " + auxDukp);

            Logger.success(
                    "BDK TR31 injetada no índice: "
                            + index
            );

        } catch (PedDevException e) {

            Logger.error(
                    "Erro ao injetar BDK TR31: "
                            + e.getMessage()
            );
        } catch (Exception e) {

            Logger.error(
                    "Erro inesperado BDK: "
                            + e.getMessage()
            );
        }
    }

}
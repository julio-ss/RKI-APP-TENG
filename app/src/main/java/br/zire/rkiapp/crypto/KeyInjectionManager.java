package br.zire.rkiapp.crypto;

import static br.zire.rkiapp.util.HexUtil.bytesToHex;

import android.content.Context;
import android.os.Build;
import android.util.Log;
import android.widget.Toast;

import com.pax.dal.IPed;
import com.pax.dal.entity.EAesCheckMode;
import com.pax.dal.entity.EPedKeyType;
import com.pax.dal.entity.EPedType;
import com.pax.dal.exceptions.PedDevException;
import com.pax.neptunelite.api.NeptuneLiteUser;
import com.pos.tectoy.security.PedKcvInfo;
import com.pos.tectoy.security.PedKeyInfo;
import com.pos.tectoy.security.PosSecurityManager;
import com.pos.tectoy.utils.PosUtils;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.rkl.RklSessionContext;
import br.zire.rkiapp.util.HexUtil;
import br.zire.rkiapp.util.Logger;
import br.zire.rkiapp.util.UiBridge;

public class KeyInjectionManager {

    String TAG = "KeyInjectionManager";

    public KeyInjectionManager() {
        ped = getPed(MainActivity.context);
    }

    byte[] buffer = new byte[16];
    IPed ped;

    //-----------------------------------------
    // INJEÇÃO TR-31
    //-----------------------------------------

    public boolean injectTr31(String tr31BlockHex, String expectedKcv, byte index) {

        try {

            UiBridge.setText("status", "Injetando chaves.");
            Logger.section("PAX TR31 INJECTION");

            if (tr31BlockHex == null || tr31BlockHex.isEmpty()) {
                Logger.error("TR31 vazio");
                return false;
            }

            ped = getPed(MainActivity.context);

            //-----------------------------------------
            // injeta TR31
            //-----------------------------------------
//            byte[] byte_kbpk = HexUtil.hexToBytes(RklSessionContext.kbpkHex);
//            Logger.info("KBPK HEX: " + HexUtil.bytesToHex(byte_kbpk));
//            injectKbpk(byte_kbpk);
            writeTR31Key(tr31BlockHex, index);

            //-----------------------------------------
            // obtém KCV device
            //-----------------------------------------
            String deviceKcv = getKcvFromDevice(ped, index);

            Logger.info("KCV esperado (HSM): " + expectedKcv);
            Logger.info("KCV dispositivo (PED): " + deviceKcv);

            //-----------------------------------------
            // WARNING apenas
            //-----------------------------------------
            if (!expectedKcv.equalsIgnoreCase(deviceKcv)) {

                UiBridge.setText("status", "Validando informações da chave.");

                Logger.warning("KCV divergente - fluxo continuará");
                Logger.warning("Possível diferença de derivação TR31 header ou modo KCV");

                RklSessionContext.setKcvMismatch(true);

            } else {

                Logger.success("KCV validado");
                RklSessionContext.setKcvMismatch(false);
            }

            return true;

        } catch (Exception e) {
            Logger.error("Erro na injeção TR31: " + e.getMessage());
            return false;
        }
    }

    //-----------------------------------------
    // ESCRITA DA CHAVE NO PED
    //-----------------------------------------
    public void writeTR31Key(String tr31Block, byte index) {

        byte[] bytesTr31 = tr31Block.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
//        byte[] byte_kbpk = HexUtil.hexToBytes(RklSessionContext.kbpkHex);
//        Logger.info("KBPK: " + RklSessionContext.kbpkHex);
        String byte_kbpk = "9B9BECEC8516B583851FC462D013A252F8CE983E7CD349071CFD681A7FE6A49D";

        if (injectKbpk(byte_kbpk)) {
                Logger.section("INJECT TR31 BLOCK");
                key(PosSecurityManager.PED_TMK, 99, 3, (int) index, 0, 0x81, 24, byte_kbpk, tr31Block);

                UiBridge.setText("status", "Chave injetada com sucesso.");
                Logger.success("TR31 SUCCESS");
        } else {
            Logger.error("TR31 ERROR: KBPK ERROR");
        }
    }

    private void key(int srcKeyType,int srcKeyIdx,int dstKeyType,int dstKeyIdx,int dstAlgorithm,int checkMode ,int len,String key,String kcv){
        PosSecurityManager posSecurityManager = PosSecurityManager.getDefault();
        PedKeyInfo pedKeyInfo = new PedKeyInfo();
        pedKeyInfo.srcKeyType = srcKeyType;
        pedKeyInfo.srcKeyIdx = srcKeyIdx;
        pedKeyInfo.dstKeyType = dstKeyType;
        pedKeyInfo.dstKeyIdx = dstKeyIdx;
        pedKeyInfo.dstKeyLen = len;
        pedKeyInfo.dstKeyData = PosUtils.hexStringToBytes(key);
        pedKeyInfo.dstAlgorithm =dstAlgorithm;
        PedKcvInfo pedKcvInfo = new PedKcvInfo();
        pedKcvInfo.checkMode = checkMode;
        pedKcvInfo.checkBuf = PosUtils.hexStringToBytes(kcv);
        int fff = posSecurityManager.PedWriteKey(pedKeyInfo,pedKcvInfo);
        Log.d(TAG, " pedKeyInfo = " +pedKeyInfo.toString());
        Log.d(TAG, " pedKcvInfo = " +pedKcvInfo.toString());
        Log.d(TAG, "PedWriteKey: " + Integer.toHexString(fff));
        if(fff == 0){
            Toast.makeText(MainActivity.context, "Write successful", Toast.LENGTH_SHORT).show();
        }else {
            Toast.makeText(MainActivity.context, "Write failed", Toast.LENGTH_SHORT).show();
        }
    }

    public boolean injectKbpk(String kbpk) {
        try {

            Logger.section("INJECT KBPK");

            if (kbpk == null)
                throw new IllegalArgumentException("KBPK null");

            //--------------------------------
            // injeta no PED
            //--------------------------------
            ped.writeAesKey(
                    EPedKeyType.AES_TMK.getPedkeyType(),
                    (byte) 0,
                    EPedKeyType.AES_TMK.getPedkeyType(),
                    (byte) 99,
                    kbpk,
                    EAesCheckMode.KCV_NONE,
                    null
            );

            Logger.success("KBPK SUCCESS");

            return true;
        } catch (Exception e) {

            Logger.error("KBPK ERROR: " + e.getMessage());

            return false;
        }
    }


    public void tr31Conversion(String tr31) {

        Logger.info("tr31 original: " + tr31);
        //--------------------------------
        // STRING → BYTE[]
        //--------------------------------
        byte[] bytes = tr31.getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        //--------------------------------
        // BYTE[] → STRING
        //--------------------------------
        String restored = new String(bytes, java.nio.charset.StandardCharsets.US_ASCII);
        Logger.info("tr31 restored: " + restored);


        //--------------------------------
        // VALIDAÇÃO
        //--------------------------------
        if (!tr31.equals(restored)) {
            throw new RuntimeException("ERRO: conversão alterou o TR31");
        }

        System.out.println("OK: conversão perfeita");
    }

    //-----------------------------------------
    // GET KCV REAL DO PED
    //-----------------------------------------

    private String getKcvFromDevice(IPed ped, byte index) {

        try {

            byte[] kcvBytes = ped.getKCV(
                    EPedKeyType.AES_TMK,
                    index,
                    (byte) 3,
                    buffer
            );

            if (kcvBytes == null || kcvBytes.length == 0)
                throw new RuntimeException("KCV retornado vazio");

            String kcv = HexUtil.bytesToHex(kcvBytes);

            Logger.info("PED raw KCV: " + kcv);

            return kcv.substring(0, 6);

        } catch (Exception e) {

            throw new RuntimeException("Erro ao obter KCV do PED", e);
        }
    }


    //-----------------------------------------
    // PED
    //-----------------------------------------

    private IPed getPed(Context context) {

        try {
            return NeptuneLiteUser.getInstance()
                    .getDal(context)
                    .getPed(EPedType.INTERNAL);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao obter PED", e);
        }
    }
}
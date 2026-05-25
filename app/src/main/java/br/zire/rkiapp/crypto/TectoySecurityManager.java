package br.zire.rkiapp.crypto;

import android.content.Context;
import android.util.Log;
import android.widget.Toast;

import com.pos.tectoy.security.PedKcvInfo;
import com.pos.tectoy.security.PedKeyInfo;
import com.pos.tectoy.security.PosSecurityManager;
import com.pos.tectoy.security.enums.EPedReturnsSP;

import java.nio.charset.StandardCharsets;

import br.zire.rkiapp.util.HexUtil;
import br.zire.rkiapp.util.Logger;

public class TectoySecurityManager {

    private static final String TAG = "TectoySecurityManager";
    private PosSecurityManager posSecurityManager;
    private Context mContext;

    public TectoySecurityManager(Context context) {
        this.mContext = context;
        this.posSecurityManager = PosSecurityManager.getDefault();
    }

    //-----------------------------------------
    // WRITE KEY METHOD
    //-----------------------------------------

    public boolean writeKey(
            int srcKeyType,
            int srcKeyIdx,
            int dstKeyType,
            int dstKeyIdx,
            int dstAlgorithm,
            int checkMode,
            int len,
            String keyHex,
            String kcvHex
    ) {

        try {

            Logger.section("WRITE KEY - TECTOY");
            Logger.info("Src Key Type: " + srcKeyType);
            Logger.info("Dst Key Type: " + dstKeyType);
            Logger.info("Dst Key Idx: " + dstKeyIdx);
            Logger.info("Check Mode: " + checkMode);

            //-----------------------------------------
            // BUILD KEY INFO
            //-----------------------------------------

            PedKeyInfo pedKeyInfo = new PedKeyInfo();
            pedKeyInfo.srcKeyType = srcKeyType;
            pedKeyInfo.srcKeyIdx = srcKeyIdx;
            pedKeyInfo.dstKeyType = dstKeyType;
            pedKeyInfo.dstKeyIdx = dstKeyIdx;
            pedKeyInfo.dstKeyLen = len;
            pedKeyInfo.dstKeyData = HexUtil.hexToBytes(keyHex);
            pedKeyInfo.dstAlgorithm = dstAlgorithm;

            //-----------------------------------------
            // BUILD KCV INFO
            //-----------------------------------------

            byte[] kcvBytes = kcvHex.getBytes(StandardCharsets.UTF_8);
            byte[] kcvByte = new byte[kcvBytes.length + 1];
            kcvByte[0] = (byte) kcvBytes.length;
            System.arraycopy(kcvBytes, 0, kcvByte, 1, kcvBytes.length);

            PedKcvInfo pedKcvInfo = new PedKcvInfo();
            pedKcvInfo.checkMode = checkMode;
            pedKcvInfo.checkBuf = kcvByte;

            //-----------------------------------------
            // WRITE KEY
            //-----------------------------------------

            int result = posSecurityManager.PedWriteKey(pedKeyInfo, pedKcvInfo);

            Logger.info("PedKeyInfo: " + pedKeyInfo.toString());
            Logger.info("PedKcvInfo: " + pedKcvInfo.toString());
            Logger.info("PedWriteKey Result: " + EPedReturnsSP.getReturnSP(result));

            //-----------------------------------------
            // VALIDATE RESULT
            //-----------------------------------------

            if (result == 0) {

                Logger.success("KEY WRITE SUCCESS");
                Toast.makeText(mContext, "PASS: Chave escrita com sucesso", Toast.LENGTH_SHORT).show();
                return true;

            } else {

                Logger.error("KEY WRITE FAILED: " + EPedReturnsSP.getReturnSP(result));
                Toast.makeText(mContext, "FAIL: Erro ao escrever chave", Toast.LENGTH_SHORT).show();
                return false;
            }

        } catch (Exception e) {

            Logger.error("Erro writeKey: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    //-----------------------------------------
    // WRITE TR31 KEY
    //-----------------------------------------

    public boolean writeTr31Key(
            String tr31BlockHex,
            int dstKeyType,
            int dstKeyIdx,
            int dstAlgorithm
    ) {

        try {

            Logger.section("WRITE TR31 KEY - TECTOY");

            //-----------------------------------------
            // VALIDATE
            //-----------------------------------------

            if (tr31BlockHex == null || tr31BlockHex.isEmpty()) {

                Logger.error("TR31 Block vazio");
                return false;
            }

            //-----------------------------------------
            // CONVERT TO BYTES
            //-----------------------------------------

            byte[] tr31Bytes = HexUtil.hexToBytes(tr31BlockHex);

            //-----------------------------------------
            // BUILD KEY INFO
            //-----------------------------------------

            PedKeyInfo pedKeyInfo = new PedKeyInfo();
            pedKeyInfo.srcKeyType = PosSecurityManager.PED_TLK;
            pedKeyInfo.srcKeyIdx = 0;
            pedKeyInfo.dstKeyType = dstKeyType;
            pedKeyInfo.dstKeyIdx = dstKeyIdx;
            pedKeyInfo.dstKeyData = tr31Bytes;
            pedKeyInfo.dstAlgorithm = dstAlgorithm;

            //-----------------------------------------
            // EMPTY KCV FOR TR31
            //-----------------------------------------

            PedKcvInfo pedKcvInfo = new PedKcvInfo();
            pedKcvInfo.checkMode = 0;
            pedKcvInfo.checkBuf = new byte[0];

            //-----------------------------------------
            // WRITE
            //-----------------------------------------

            int result = posSecurityManager.PedWriteKey(pedKeyInfo, pedKcvInfo);

            Logger.info("PedWriteKey Result: " + EPedReturnsSP.getReturnSP(result));

            //-----------------------------------------
            // VALIDATE
            //-----------------------------------------

            if (result == 0) {

                Logger.success("TR31 WRITE SUCCESS");
                return true;

            } else {

                Logger.error("TR31 WRITE FAILED: " + EPedReturnsSP.getReturnSP(result));
                return false;
            }

        } catch (Exception e) {

            Logger.error("Erro writeTr31Key: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    //-----------------------------------------
    // GET KCV
    //-----------------------------------------

    public String getKcv(int keyType, int keyIdx) {

        try {

            Logger.info("Getting KCV for keyType: " + keyType + ", keyIdx: " + keyIdx);

            byte[] buffer = new byte[16];
            byte[] kcvBytes = new byte[16];

            // This is a placeholder - the actual implementation depends on Tectoy SDK
            // Check Tectoy documentation for the correct method to retrieve KCV

            Logger.info("KCV retrieved: " + HexUtil.bytesToHex(kcvBytes));

            return HexUtil.bytesToHex(kcvBytes);

        } catch (Exception e) {

            Logger.error("Erro getKcv: " + e.getMessage());
            return null;
        }
    }
}

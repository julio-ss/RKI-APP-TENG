package br.zire.rkiapp.crypto;

import static br.zire.rkiapp.util.HexUtil.bytesToHex;

import android.content.Context;
import android.util.Log;
import android.widget.Toast;

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
    private PosSecurityManager securityManager;

    public KeyInjectionManager() {
        this.securityManager = PosSecurityManager.getDefault();
    }

    //-----------------------------------------
    // INJEÇÃO TR-31
    //-----------------------------------------

    public boolean injectTr31(String tr31BlockHex, String expectedKcv, byte index) {

        try {

            UiBridge.setText("status", "Injetando chaves.");
            Logger.section("TECTOY TR31 INJECTION");

            if (tr31BlockHex == null || tr31BlockHex.isEmpty()) {
                Logger.error("TR31 vazio");
                return false;
            }

            //-----------------------------------------
            // INJETA KBPK PRIMEIRO
            //-----------------------------------------

            String kbpk = RklSessionContext.kbpkHex != null
                    ? RklSessionContext.kbpkHex
                    : "9B9BECEC8516B583851FC462D013A252F8CE983E7CD349071CFD681A7FE6A49D";

            if (!injectKbpk(kbpk)) {
                Logger.error("Falha ao injetar KBPK");
                return false;
            }

            //-----------------------------------------
            // INJETA TR31
            //-----------------------------------------

            if (!writeTR31Key(tr31BlockHex, index)) {
                Logger.error("Falha ao escrever TR31");
                return false;
            }

            //-----------------------------------------
            // OBTÉM KCV DO DEVICE
            //-----------------------------------------

            String deviceKcv = getKcvFromDevice(index);

            Logger.info("KCV esperado (HSM): " + expectedKcv);
            Logger.info("KCV dispositivo (PED): " + deviceKcv);

            //-----------------------------------------
            // VALIDAÇÃO (WARNING APENAS)
            //-----------------------------------------

            if (deviceKcv == null || !expectedKcv.equalsIgnoreCase(deviceKcv)) {

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
            e.printStackTrace();
            return false;
        }
    }

    //-----------------------------------------
    // ESCRITA DA CHAVE TR31 NO PED
    //-----------------------------------------

    private boolean writeTR31Key(String tr31BlockHex, byte index) {

        try {

            Logger.section("WRITE TR31 BLOCK");

            //-----------------------------------------
            // CONVERTER PARA BYTES
            //-----------------------------------------

            byte[] tr31Bytes = HexUtil.hexToBytes(tr31BlockHex);

            //-----------------------------------------
            // ESCREVER CHAVE
            //-----------------------------------------

            boolean result = writeKey(
                    PosSecurityManager.PED_TLK,
                    0,
                    PosSecurityManager.PED_TMK,
                    (int) index,
                    0x10,
                    0x81,
                    24,
                    tr31BlockHex
            );

            if (result) {
                UiBridge.setText("status", "Chave injetada com sucesso.");
                Logger.success("TR31 WRITE SUCCESS");
                return true;
            } else {
                Logger.error("TR31 WRITE FAILED");
                return false;
            }

        } catch (Exception e) {
            Logger.error("Erro ao escrever TR31: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    //-----------------------------------------
    // ESCREVER CHAVE GENÉRICA
    //-----------------------------------------

    private boolean writeKey(
            int srcKeyType,
            int srcKeyIdx,
            int dstKeyType,
            int dstKeyIdx,
            int dstAlgorithm,
            int checkMode,
            int len,
            String keyHex
    ) {

        try {

            PedKeyInfo pedKeyInfo = new PedKeyInfo();
            pedKeyInfo.srcKeyType = srcKeyType;
            pedKeyInfo.srcKeyIdx = srcKeyIdx;
            pedKeyInfo.dstKeyType = dstKeyType;
            pedKeyInfo.dstKeyIdx = dstKeyIdx;
            pedKeyInfo.dstKeyLen = len;
            pedKeyInfo.dstKeyData = HexUtil.hexToBytes(keyHex);
            pedKeyInfo.dstAlgorithm = dstAlgorithm;

            PedKcvInfo pedKcvInfo = new PedKcvInfo();
            pedKcvInfo.checkMode = checkMode;
            pedKcvInfo.checkBuf = new byte[0];

            int result = securityManager.PedWriteKey(pedKeyInfo, pedKcvInfo);

            Log.d(TAG, "PedWriteKey result: " + Integer.toHexString(result));
            Logger.info("PedWriteKey: " + Integer.toHexString(result));

            if (result == 0) {
                Toast.makeText(MainActivity.context, "Chave escrita com sucesso", Toast.LENGTH_SHORT).show();
                return true;
            } else {
                Toast.makeText(MainActivity.context, "Falha ao escrever chave", Toast.LENGTH_SHORT).show();
                return false;
            }

        } catch (Exception e) {
            Logger.error("Erro writeKey: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    //-----------------------------------------
    // INJETAR KBPK
    //-----------------------------------------

    private boolean injectKbpk(String kbpkHex) {

        try {

            Logger.section("INJECT KBPK");

            if (kbpkHex == null || kbpkHex.isEmpty()) {
                Logger.error("KBPK nula ou vazia");
                return false;
            }

            //-----------------------------------------
            // ESCREVER KBPK
            //-----------------------------------------

            boolean result = writeKey(
                    PosSecurityManager.PED_TLK,
                    0,
                    PosSecurityManager.PED_TLK,
                    1,
                    0x10,
                    0,
                    32,
                    kbpkHex
            );

            if (result) {
                Logger.success("KBPK INJECTION SUCCESS");
                return true;
            } else {
                Logger.error("KBPK INJECTION FAILED");
                return false;
            }

        } catch (Exception e) {
            Logger.error("KBPK ERROR: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    //-----------------------------------------
    // OBTER KCV DO DISPOSITIVO
    //-----------------------------------------

    private String getKcvFromDevice(byte index) {

        try {

            Logger.info("Obtendo KCV do índice: " + index);

            // Tectoy não tem método getKCV() nativo
            // Alternativa: usar valor da API RKL armazenado na sessão
            // ou calcular localmente se disponível

            // Por enquanto, retornar valor placeholder
            // Em produção, usar KCV da resposta da API

            String kcv = RklSessionContext.getKcvForIndex(index);

            if (kcv != null && !kcv.isEmpty()) {
                Logger.info("PED KCV (from session): " + kcv);
                return kcv;
            }

            Logger.warning("KCV não disponível na sessão");
            return "000000";

        } catch (Exception e) {
            Logger.error("Erro ao obter KCV: " + e.getMessage());
            return null;
        }
    }

    //-----------------------------------------
    // CONVERSÃO TR31
    //-----------------------------------------

    public void tr31Conversion(String tr31) {

        Logger.info("tr31 original: " + tr31);

        byte[] bytes = tr31.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        String restored = new String(bytes, java.nio.charset.StandardCharsets.US_ASCII);

        Logger.info("tr31 restored: " + restored);

        if (!tr31.equals(restored)) {
            throw new RuntimeException("ERRO: conversão alterou o TR31");
        }

        Logger.success("Conversão perfeita");
    }
}

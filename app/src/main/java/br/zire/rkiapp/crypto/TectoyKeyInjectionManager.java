package br.zire.rkiapp.crypto;

import android.content.Context;

import com.pos.tectoy.sdk.PosSecurityManager;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.rkl.RklSessionContext;
import br.zire.rkiapp.rkl.model.RklProfileKey;
import br.zire.rkiapp.util.HexUtil;
import br.zire.rkiapp.util.Logger;
import br.zire.rkiapp.util.UiBridge;

public class TectoyKeyInjectionManager {

    //-----------------------------------------
    // SECURITY MANAGER
    //-----------------------------------------

    private TectoySecurityManager securityManager;

    //-----------------------------------------
    // CONSTRUCTOR
    //-----------------------------------------

    public TectoyKeyInjectionManager(Context context) {
        this.securityManager = new TectoySecurityManager(context);
    }

    //-----------------------------------------
    // INJECT TR31
    //-----------------------------------------

    public boolean injectTr31(RklProfileKey profileKey, String tr31BlockHex) {

        try {

            //-----------------------------------------
            // VALIDATIONS
            //-----------------------------------------

            if (profileKey == null) {
                Logger.error("ProfileKey null");
                return false;
            }

            if (tr31BlockHex == null || tr31BlockHex.trim().isEmpty()) {
                Logger.error("TR31 vazio");
                return false;
            }

            //-----------------------------------------
            // LOG
            //-----------------------------------------

            Logger.section("TR31 INJECTION - TECTOY");
            Logger.info("LABEL: " + profileKey.label);
            Logger.info("SLOT: " + profileKey.slotTargetPhy);
            Logger.info("KEY TYPE: " + (profileKey.isMk() ? "MK" : "BDK"));

            //-----------------------------------------
            // INJECT KBPK (if needed)
            //-----------------------------------------

            if (!injectKbpk()) {
                Logger.error("Falha KBPK");
                return false;
            }

            //-----------------------------------------
            // WRITE TR31
            //-----------------------------------------

            boolean writeResult = writeTr31Key(tr31BlockHex);

            if (!writeResult) {
                Logger.error("Falha ao escrever TR31");
                return false;
            }

            //-----------------------------------------
            // SUCCESS
            //-----------------------------------------

            Logger.success("KEY INJECTION SUCCESS");

            UiBridge.setText(
                    "status",
                    "Chave injetada"
            );

            return true;

        } catch (Exception e) {

            Logger.error(
                    "Erro injeção: "
                            + e.getMessage()
            );

            e.printStackTrace();

            return false;
        }
    }

    //-----------------------------------------
    // WRITE TR31
    //-----------------------------------------

    private boolean writeTr31Key(String tr31Block) {

        try {

            Logger.section("WRITE TR31");

            //-----------------------------------------
            // VALIDATE
            //-----------------------------------------

            if (tr31Block == null || tr31Block.isEmpty()) {
                Logger.error("TR31 inválido");
                return false;
            }

            //-----------------------------------------
            // DETERMINE KEY TYPE AND INDEX
            //-----------------------------------------

            // Based on the Tectoy SDK example provided by the user
            int dstKeyType = PosSecurityManager.PED_TMK;
            int dstKeyIdx = 1;
            int dstAlgorithm = 0x10;

            //-----------------------------------------
            // WRITE
            //-----------------------------------------

            boolean result = securityManager.writeTr31Key(
                    tr31Block,
                    dstKeyType,
                    dstKeyIdx,
                    dstAlgorithm
            );

            if (!result) {
                Logger.error("Falha ao escrever TR31");
                return false;
            }

            Logger.success("TR31 WRITE SUCCESS");

            return true;

        } catch (Exception e) {

            Logger.error(
                    "WRITE TR31 ERROR: "
                            + e.getMessage()
            );

            return false;
        }
    }

    //-----------------------------------------
    // INJECT KBPK
    //-----------------------------------------

    private boolean injectKbpk() {

        try {

            Logger.section("INJECT KBPK - TECTOY");

            //-----------------------------------------
            // VALIDATE
            //-----------------------------------------

            if (RklSessionContext.kbpkHex == null || RklSessionContext.kbpkPlain.length == 0) {
                Logger.error("KBPK inválida");
                return false;
            }

            //-----------------------------------------
            // KBPK VALUES
            //-----------------------------------------

            String kbpkHex = RklSessionContext.kbpkHex;
            String kbpkCheckBuf = "354176"; // Default check value

            //-----------------------------------------
            // WRITE
            //-----------------------------------------

            boolean result = securityManager.writeKey(
                    PosSecurityManager.PED_TLK,
                    0,
                    PosSecurityManager.PED_TLK,
                    1,
                    0x10,
                    0,
                    32,
                    kbpkHex,
                    kbpkCheckBuf
            );

            if (!result) {
                Logger.error("Falha ao escrever KBPK");
                return false;
            }

            Logger.success("KBPK SUCCESS");

            return true;

        } catch (Exception e) {

            Logger.error(
                    "KBPK ERROR: "
                            + e.getMessage()
            );

            return false;
        }
    }
}

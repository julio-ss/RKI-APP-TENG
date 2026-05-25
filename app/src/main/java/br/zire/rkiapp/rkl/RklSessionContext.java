package br.zire.rkiapp.rkl;

import java.security.PrivateKey;
import java.security.PublicKey;

import br.zire.rkiapp.rkl.model.RklProfile;
import br.zire.rkiapp.rkl.model.RklProfileKey;
import br.zire.rkiapp.util.Logger;

public class RklSessionContext {

    public static String identifierKeyToBeLoad;

    //-----------------------------------------
    // PROFILE
    //-----------------------------------------

    //--------------------------------
    // PIN KEY
    //--------------------------------

    public static int pinKeyId;
    public static String pinKeyLabel;
    public static int pinKeySlot;
    public static String pinKeyKsi;
    public static int pinKeyIpekSize;

//--------------------------------
// DATA KEY
//--------------------------------

    public static int dataKeyId;
    public static String dataKeyLabel;
    public static int dataKeySlot;
    public static String dataKeyKsi;
    public static int dataKeyIpekSize;

    public static RklProfile profile;

    public static RklProfileKey mkProfileKey;
    public static RklProfileKey bdkProfileKey;

    //-----------------------------------------
    // KBPK
    //-----------------------------------------

    public static String kbpkHex;
    public static byte[] kbpkPlain;
    public static String kbpk;

    //-----------------------------------------
    // CERTIFICADOS
    //-----------------------------------------

    public static String ephemeralCertificatePem;
    public static PublicKey posPublicKey;

    public static String rootCa;
    public static String intermediateCa;

    public static String posCertificatePem;
    public static String posCertificateB64;

    public static String certX509;

    public static PublicKey ephemeralPublicKey;
    public static PrivateKey privateKey;

    //-----------------------------------------
    // TR31
    //-----------------------------------------

    public static String tr31KeyBlock;
    public static String mkTr31KeyBlock;
    public static String bdkTr31KeyBlock;
    public static String bdkTr31Kcv;
    public static String bdkKcv;
    public static String kcv;
    public static String mkTr31kcv;
    public static String bdkTr31kcv;

    //-----------------------------------------
    // CONTROLE DE VALIDAÇÃO
    //-----------------------------------------

    private static boolean kcvMismatch = false;

    //-----------------------------------------
    // REQUEST CONTROL
    //-----------------------------------------

    public static String transactionId;
    public static String csr;
    public static String token;

    //-----------------------------------------
    // RESET
    //-----------------------------------------

    public static void reset() {
        resetSession();
    }

    /**
     * Reinicia a sessão RKL
     */
    public static void resetSession() {

        Logger.section("RESET SESSION");

        kbpkHex = null;
        kbpkPlain = null;
        kbpk = null;

        ephemeralCertificatePem = null;
        posPublicKey = null;

        rootCa = null;
        intermediateCa = null;

        posCertificateB64 = null;
        posCertificatePem = null;

        certX509 = null;

        ephemeralPublicKey = null;
        privateKey = null;

        tr31KeyBlock = null;
        kcv = null;

        token = null;
        transactionId = null;
        csr = null;

        kcvMismatch = false;
    }

    //-----------------------------------------
    // KCV STATE CONTROL
    //-----------------------------------------

    public static void setKcvMismatch(boolean value) {

        kcvMismatch = value;

        Logger.section("KCV STATUS");

        if (value) {

            Logger.warning("KCV mismatch detectado");
            Logger.warning("fluxo RKI continuará conforme especificação");

        } else {

            Logger.info("KCV validado com sucesso");
        }
    }

    public static boolean isKcvMismatch() {
        return kcvMismatch;
    }

}
package br.zire.rkiapp.crypto;

import android.util.Base64;

import java.security.PublicKey;

import javax.crypto.Cipher;

import br.zire.rkiapp.util.Logger;

public class RsaCryptoManager {

    /**
     * Implementação 1:1 com backend (.NET + BouncyCastle)
     *
     * HEX → byte[] → RSA PKCS1 → Base64
     */
    public static String encryptKbpk(String clearTextHex, PublicKey publicKey) {

        try {
            Logger.info("KBPK - Algoritmo chave: " + publicKey.getAlgorithm());
            Logger.info("PublicKey class: " + publicKey.getClass().getName());
            Logger.info("Algorithm: " + publicKey.getAlgorithm());

            //--------------------------------
            // VALIDAÇÃO
            //--------------------------------
            if (clearTextHex == null || clearTextHex.length() != 64) {
                Logger.error("KBPK HEX inválida");
                return null;
            }

            //--------------------------------
            // HEX → BYTE[]
            //--------------------------------
            byte[] bytesToEncrypt = hexToBytesStrict(clearTextHex);

            Logger.info("KBPK bytes length: " + bytesToEncrypt.length); // deve ser 32

            //--------------------------------
            // RSA PKCS1
            //--------------------------------
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            //--------------------------------
            // PROCESS BLOCK
            //--------------------------------
            byte[] encryptedBytes = cipher.doFinal(bytesToEncrypt);// assinar

            //--------------------------------
            // BASE64 FINAL
            //--------------------------------
            String encryptedBase64 = // vai no json
                    Base64.encodeToString(encryptedBytes, Base64.NO_WRAP);

            //Encriptar aqui


            Logger.info("Encrypted KBPK length: " + encryptedBase64.length());

            return encryptedBase64;

        } catch (Exception e) {

            Logger.error("Erro ao criptografar KBPK");
            e.printStackTrace();
            return null;
        }
    }

    //--------------------------------
    // HEX → BYTE[]
    //--------------------------------
    private static byte[] hexToBytesStrict(String hex) {

        int len = hex.length();

        if (len % 2 != 0) {
            throw new IllegalArgumentException("HEX inválido");
        }

        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {

            int high = Character.digit(hex.charAt(i), 16);
            int low = Character.digit(hex.charAt(i + 1), 16);

            if (high == -1 || low == -1) {
                throw new IllegalArgumentException("HEX inválido");
            }

            data[i / 2] = (byte) ((high << 4) + low);
        }

        return data;
    }
}
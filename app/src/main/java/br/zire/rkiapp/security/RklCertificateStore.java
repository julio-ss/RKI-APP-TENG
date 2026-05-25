package br.zire.rkiapp.security;

import android.content.Context;
import android.util.Base64;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.PublicKey;

import br.zire.rkiapp.util.Logger;

public class RklCertificateStore {

    //--------------------------------
    // FILE NAMES
    //--------------------------------

    public static final String POS_CERT = "pos_cert.pem";
    public static final String EPHEMERAL_CERT = "ephemeral_cert.pem";

    //--------------------------------
    // SAVE
    //--------------------------------

    public static void save(Context context, String certInput, String fileName) {

        try {

            String certPem = normalizeToPem(certInput);

            File file = new File(context.getFilesDir(), fileName);

            FileOutputStream fos = new FileOutputStream(file);
            fos.write(certPem.getBytes());
            fos.close();

            Logger.success("✓ Certificado salvo em disco: " + fileName);

        } catch (Exception e) {

            Logger.error("Erro ao salvar certificado: " + fileName);
            e.printStackTrace();
        }
    }

    //--------------------------------
    // LOAD
    //--------------------------------

    public static String load(Context context, String fileName) {

        try {

            File file = new File(context.getFilesDir(), fileName);

            if (!file.exists()) {

                Logger.warning("Certificado não encontrado: " + fileName);
                return null;
            }

            FileInputStream fis = new FileInputStream(file);

            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();

            String cert = new String(data);

            cert = normalizeToPem(cert);

            Logger.success("✓ Certificado carregado: " + fileName);

            return cert;

        } catch (Exception e) {

            Logger.error("Erro ao carregar certificado: " + fileName);
            e.printStackTrace();

            return null;
        }
    }

    //--------------------------------
    // EXISTS
    //--------------------------------

    public static boolean exists(Context context, String fileName) {

        File file = new File(context.getFilesDir(), fileName);
        return file.exists();
    }

    //--------------------------------
    // NORMALIZAÇÃO CRÍTICA
    //--------------------------------

    private static String normalizeToPem(String input) {

        try {

            if (input == null) return null;

            if (input.contains("BEGIN CERTIFICATE")) {
                return input;
            }

            if (input.startsWith("LS0t")) {

                Logger.warning("Certificado estava em Base64 → convertendo para PEM");

                byte[] decoded = Base64.decode(input, Base64.NO_WRAP);

                return new String(decoded);
            }

            return input;

        } catch (Exception e) {

            Logger.error("Erro ao normalizar certificado");
            e.printStackTrace();
            return input;
        }
    }

    public static PublicKey loadEphemeralPublicKey(Context context) {

        try {

            String cert = RklCertificateStore.load(
                    context,
                    RklCertificateStore.EPHEMERAL_CERT
            );

            if (cert == null) {
                Logger.error("Certificado efêmero não encontrado no disco");
                return null;
            }

            PublicKey key = RklCertificateParser.extractPublicKey(cert);

            if (key == null) {
                Logger.error("Falha ao extrair PublicKey do certificado efêmero");
                return null;
            }

            return key;

        } catch (Exception e) {

            Logger.error("Erro ao carregar chave pública efêmera");
            e.printStackTrace();
            return null;
        }
    }
}
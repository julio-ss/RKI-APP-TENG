package br.zire.rkiapp.crypto;

import br.zire.rkiapp.util.Logger;

public class Tr31Parser {

    public static class Tr31Data {

        public String raw;
        public String header;
        public String keyBlock;
        public String mac;

        public String version;
        public int length;
        public String keyUsage;
        public String algorithm;
        public String modeOfUse;
        public String exportability;

        public boolean isValid;
    }

    //----------------------------------------
    // PARSE PRINCIPAL
    //----------------------------------------

    public static Tr31Data parse(String tr31) {

        Tr31Data data = new Tr31Data();

        try {

            Logger.section("TR31 PARSER");

            if (tr31 == null || tr31.length() < 32) {
                Logger.error("TR31 inválido ou muito curto");
                data.isValid = false;
                return data;
            }

            data.raw = tr31;

            //----------------------------------------
            // HEADER (primeiros 16 chars normalmente)
            //----------------------------------------

            data.header = tr31.substring(0, 16);

            //----------------------------------------
            // MAC (últimos 16 bytes hex = 32 chars)
            //----------------------------------------

            data.mac = tr31.substring(tr31.length() - 32);

            //----------------------------------------
            // KEY BLOCK (meio)
            //----------------------------------------

            data.keyBlock = tr31.substring(16, tr31.length() - 32);

            //----------------------------------------
            // PARSE HEADER
            //----------------------------------------

            data.version = data.header.substring(0, 1);

            data.length = Integer.parseInt(
                    data.header.substring(1, 5)
            );

            data.keyUsage = data.header.substring(5, 7);

            data.algorithm = data.header.substring(7, 8);

            data.modeOfUse = data.header.substring(8, 9);

            data.exportability = data.header.substring(9, 10);

            //----------------------------------------
            // LOG SEGURO
            //----------------------------------------

            Logger.info("TR31 Version: " + data.version);
            Logger.info("Length: " + data.length);
            Logger.info("KeyUsage: " + data.keyUsage);
            Logger.info("Algorithm: " + data.algorithm);
            Logger.info("ModeOfUse: " + data.modeOfUse);
            Logger.info("Exportability: " + data.exportability);

            Logger.info("Header Length: " + data.header.length());
            Logger.info("KeyBlock Length: " + data.keyBlock.length());
            Logger.info("MAC Length: " + data.mac.length());

            data.isValid = true;

            return data;

        } catch (Exception e) {

            Logger.error("Erro ao parsear TR31");
            e.printStackTrace();

            data.isValid = false;
            return data;
        }
    }
}
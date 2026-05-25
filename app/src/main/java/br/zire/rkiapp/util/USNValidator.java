package br.zire.rkiapp.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Responsável por validar e formatar o USN (Unique Serial Number)
 * exigido pelo servidor RKI.
 *
 * Regra:
 * O USN deve possuir exatamente 26 caracteres.
 * Caso o Serial Number seja menor que 26 caracteres,
 * será realizado left pad com o caractere 'F'.
 */
public class USNValidator {

    private static final String TAG = USNValidator.class.getSimpleName();
    private static final int USN_LENGTH = 26;
    private static final int REQUIRED_USN_LENGTH = 26;

    private USNValidator() {
        // Evita instanciação
    }

    /**
     * Formata o Serial Number para USN com 26 caracteres.
     *
     * @param serialNumber SN obtido do terminal POS
     * @return USN formatado com 26 caracteres
     * @throws IllegalArgumentException caso SN seja nulo ou maior que 26
     */
    public static String formatToUSN(String serialNumber) {
        Logger.section("Format to USN");

        if (serialNumber == null) {
            Logger.error("SerialNumber is null");
            throw new IllegalArgumentException("SerialNumber cannot be null");
        }

        String sanitizedSN = serialNumber.trim();

        if (sanitizedSN.isEmpty()) {
            Logger.error("SerialNumber is empty");
            throw new IllegalArgumentException("SerialNumber cannot be empty");
        }

        if (sanitizedSN.length() > REQUIRED_USN_LENGTH) {

            Logger.error(
                    "SerialNumber length greater than allowed | length=" + sanitizedSN.length()
            );

            throw new IllegalArgumentException(
                    "SerialNumber length cannot be greater than 26 characters"
            );
        }

        int missingChars = REQUIRED_USN_LENGTH - sanitizedSN.length();

        StringBuilder usnBuilder = new StringBuilder();

        for (int i = 0; i < missingChars; i++) {
            usnBuilder.append("F");
        }

        usnBuilder.append(sanitizedSN);

        String usn = usnBuilder.toString();

        Logger.info(
                "USN formatted successfully | " +
                        "originalLength=" + sanitizedSN.length() +
                " | finalLength=" + usn.length()
        );

        return usn;
    }

    /**
     * Gera USN baseado em SHA-256 do serial do terminal.
     *
     * Regras:
     * - HEX uppercase
     * - 26 caracteres
     * - determinístico
     * - sem caracteres inválidos
     */
    public static String generateUsn(String serialNumber) {
        try {

            if (serialNumber == null || serialNumber.trim().isEmpty()) {
                throw new IllegalArgumentException("Serial number inválido");
            }

            String normalized = serialNumber.trim().toUpperCase();

            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] hashBytes = digest.digest(
                    normalized.getBytes(StandardCharsets.UTF_8)
            );

            StringBuilder hexBuilder = new StringBuilder();

            for (byte b : hashBytes) {
                hexBuilder.append(String.format("%02X", b));
            }

            String hexHash = hexBuilder.toString();

            return hexHash.substring(0, USN_LENGTH);

        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar USN", e);
        }
    }
}
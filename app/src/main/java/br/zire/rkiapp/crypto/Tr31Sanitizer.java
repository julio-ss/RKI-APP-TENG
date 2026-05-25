package br.zire.rkiapp.crypto;

public class Tr31Sanitizer {

    private Tr31Sanitizer() {
    }

    public static String sanitize(String tr31) {

        if (tr31 == null) {
            return null;
        }

        return tr31
                .replace(" ", "")
                .replace("\n", "")
                .replace("\r", "")
                .trim()
                .toUpperCase();
    }
}
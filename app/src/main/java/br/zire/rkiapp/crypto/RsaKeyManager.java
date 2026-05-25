package br.zire.rkiapp.crypto;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import br.zire.rkiapp.util.Logger;

public class RsaKeyManager {

    private static final String ZIRE_KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "RKI_RSA_KEY";

    public static boolean keyExists() {
        Logger.section("CHECANDO SE CHAVE EXISTE");
        try {
            KeyStore keyStore = KeyStore.getInstance(ZIRE_KEYSTORE);
            keyStore.load(null);
            return keyStore.containsAlias(KEY_ALIAS);
        } catch (Exception e) {
            return false;
        }
    }

    public static KeyPair generateKeyIfNeeded() throws Exception {

        if (keyExists()) {
            Logger.info("Chave já existe");
            return getKeyPair();
        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA,
                ZIRE_KEYSTORE
        );

        // CORREÇÃO: adicionar DECRYPT + OAEP
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN |
                        KeyProperties.PURPOSE_VERIFY |
                        KeyProperties.PURPOSE_DECRYPT
        )
                .setKeySize(2048)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .build();

        keyPairGenerator.initialize(spec);

        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair getKeyPair() throws Exception {
        Logger.section("CARREGANDO CHAVE");

        KeyStore keyStore = KeyStore.getInstance(ZIRE_KEYSTORE);
        keyStore.load(null);

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);
        PublicKey publicKey = keyStore.getCertificate(KEY_ALIAS).getPublicKey();

        return new KeyPair(publicKey, privateKey);
    }
}
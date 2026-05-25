package br.zire.rkiapp.rkl;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.crypto.RsaKeyInspector;
import br.zire.rkiapp.crypto.RsaKeyManager;
import br.zire.rkiapp.domain.SerialNumberDatails;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.rkl.model.RklProfileKey;
import br.zire.rkiapp.util.Logger;
import br.zire.rkiapp.util.UiBridge;

public class TectoyRklFlowManager {

    //------------------------------------
    // MANAGERS
    //------------------------------------

    private final RklConnectivityManager connectivityManager;

    private final RklAuthManager authManager;

    private final RklCertificateManager certificateManager;

    private final RklEphemeralCertificateManager ephemeralManager;

    private final RklIssuePosCertificateManager issueManager;

    private final TectoyRklLoadKbpkManager loadKbpkManager;

    private final TectoyRklLoadMkManager loadMkManager;

    private final TectoyRklLoadBdkManager loadBdkManager;

    private final RklSerialNumberStatusManager serialStatusManager;

    private final SerialNumberDatails serialNumberDatails;

    //------------------------------------
    // CONFIG
    //------------------------------------

    private static final int MAX_RETRY = 3;

    private static final int TIMEOUT_SECONDS = 5;

    //------------------------------------
    // CONSTRUCTOR
    //------------------------------------

    public TectoyRklFlowManager(RklHttpClient httpClient) {

        connectivityManager = new RklConnectivityManager(httpClient);
        authManager = new RklAuthManager(httpClient);
        certificateManager = new RklCertificateManager(httpClient);
        ephemeralManager = new RklEphemeralCertificateManager(httpClient);
        issueManager = new RklIssuePosCertificateManager(httpClient);
        loadKbpkManager = new TectoyRklLoadKbpkManager(httpClient);
        loadMkManager = new TectoyRklLoadMkManager(httpClient);
        loadBdkManager = new TectoyRklLoadBdkManager(httpClient);
        serialStatusManager = new RklSerialNumberStatusManager(httpClient);
        serialNumberDatails = new SerialNumberDatails(httpClient);
    }

    //------------------------------------
    // START FLOW
    //------------------------------------

    public void startFlow() {

        new Thread(() -> {

            try {
                Logger.section("INICIANDO FLUXO RKL - TECTOY");

                //------------------------------------
                // RESET
                //------------------------------------

                RklSessionContext.resetSession();

                //------------------------------------
                // TRANSACTION
                //------------------------------------

                RklSessionContext.transactionId =
                        RklEphemeralCertificateManager
                                .generateTransactionId();

                //------------------------------------
                // CONNECTIVITY
                //------------------------------------

                connectivityManager.testServers();

                Thread.sleep(1000);

                //------------------------------------
                // AUTH
                //------------------------------------

                authManager.requestToken();

                Thread.sleep(1000);

                //------------------------------------
                // SERIAL DETAILS
                //------------------------------------

                serialNumberDatails
                        .requestSerialNumberDetails();

                if (RklSessionContext.profileKeys == null
                        || RklSessionContext.profileKeys.isEmpty()) {

                    throw new IllegalStateException(
                            "Nenhuma chave profile carregada"
                    );
                }

                //------------------------------------
                // CERTIFICATE CHAIN
                //------------------------------------

                certificateManager
                        .requestCertificateChain();

                Thread.sleep(1000);

                //------------------------------------
                // KEYPAIR
                //------------------------------------

                KeyPair keyPair =
                        RsaKeyManager
                                .generateKeyIfNeeded();

                if (keyPair == null) {

                    throw new IllegalStateException(
                            "KeyPair null"
                    );
                }

                PublicKey publicKey =
                        keyPair.getPublic();

                PrivateKey privateKey =
                        keyPair.getPrivate();

                RklSessionContext.privateKey =
                        privateKey;

                //------------------------------------
                // EPHEMERAL CERTIFICATE
                //------------------------------------

                boolean ephemeralResponse =
                        ephemeralManager
                                .requestEphemeralCertificate(
                                        MainActivity.context
                                );

                String logPublic =
                        RsaKeyInspector
                                .extractModulusFromPublicKey(
                                        RklSessionContext
                                                .ephemeralPublicKey
                                );

                Logger.info(
                        "Ephemeral PublicKey: "
                                + logPublic
                );

                if (!ephemeralResponse) {

                    Logger.warning(
                            "Certificado efêmero não recebido"
                    );
                }

                //------------------------------------
                // CSR
                //------------------------------------

                String csr =
                        RklCsrGenerator
                                .generateCsrPem(
                                        keyPair,
                                        MainActivity.USN
                                );

                if (csr == null) {

                    UiBridge.setText(
                            "status",
                            "Falha CSR"
                    );

                    Logger.error(
                            "CSR null"
                    );

                    return;
                }

                RklSessionContext.csr =
                        csr;

                //------------------------------------
                // CERTIFICATE ISSUE
                //------------------------------------

                issueManager
                        .requestCertificateIssue();

                Thread.sleep(1000);

                //------------------------------------
                // LOAD KBPK (TECTOY)
                //------------------------------------

                boolean kbpkOk =
                        executeWithRetry(
                                "LOAD KBPK (TECTOY)",
                                () -> loadKbpkManager
                                        .loadKbpk()
                        );

                if (!kbpkOk) {

                    throw new IllegalStateException(
                            "Falha KBPK"
                    );
                }

                //------------------------------------
                // STATUS
                //------------------------------------

                serialStatusManager.updateStatus(RklSerialNumberStatusManager.STATUS_EXECUTING);

                //------------------------------------
                // PROFILE KEYS
                //------------------------------------

                Logger.section("LOAD PROFILE KEYS - TECTOY");

                for (RklProfileKey profileKey :
                        RklSessionContext.profileKeys) {

                    //------------------------------------
                    // MK (TECTOY)
                    //------------------------------------

                    if (profileKey.isMk()) {

                        boolean mkOk =
                                executeWithRetry(
                                        "Inserindo chave MK (TECTOY)",
                                        () -> loadMkManager
                                                .loadMk(
                                                        profileKey
                                                )
                                );

                        if (!mkOk) {

                            Logger.error(
                                    "Falha ao inserir MK"
                            );

                            UiBridge.setText(
                                    "status",
                                    "Falha: chave MK não foi inserida"
                            );

                            throw new IllegalStateException(
                                    "Falha MK: "
                                            + profileKey.label
                            );
                        }

                        Logger.success(
                                "MK inserida com sucesso"
                        );

                        UiBridge.setText(
                                "status",
                                "✓ Chave MK inserida"
                        );
                    }

                    //------------------------------------
                    // BDK (TECTOY)
                    //------------------------------------

                    if (profileKey.isBdk()) {

                        boolean bdkOk =
                                executeWithRetry(
                                        "Inserindo chave BDK (TECTOY)",
                                        () -> loadBdkManager
                                                .loadBdk(
                                                        profileKey
                                                )
                                );

                        if (!bdkOk) {

                            Logger.error(
                                    "Falha ao inserir BDK"
                            );

                            UiBridge.setText(
                                    "status",
                                    "Falha: chave BDK não foi inserida"
                            );

                            throw new IllegalStateException(
                                    "Falha BDK: "
                                            + profileKey.label
                            );
                        }

                        Logger.success(
                                "BDK inserida com sucesso"
                        );

                        UiBridge.setText(
                                "status",
                                "✓ Chave BDK inserida"
                        );
                    }
                }

                //------------------------------------
                // VALIDATE PUBLIC KEY
                //------------------------------------

                String before =
                        RsaKeyInspector
                                .extractModulusFromPublicKey(
                                        RklSessionContext
                                                .ephemeralPublicKey
                                );

                String after =
                        RsaKeyInspector
                                .extractModulusFromPublicKey(
                                        publicKey
                                );

                if (!before.equals(after)) {

                    Logger.error(
                            "PublicKey divergente"
                    );

                    throw new IllegalStateException(
                            "PublicKey inconsistente"
                    );
                }

                //------------------------------------
                // STATUS SUCCESS
                //------------------------------------

                serialStatusManager.updateStatus(RklSerialNumberStatusManager.STATUS_SUCCESS);

                //------------------------------------
                // SUCCESS
                //------------------------------------

                Logger.success("FLUXO RKI FINALIZADO - TECTOY");

                UiBridge.setText(
                        "status",
                        "RKI concluído"
                );

            } catch (Exception e) {

                Logger.error(
                        "Erro fluxo RKL: "
                                + e.getMessage()
                );

                try {

                    serialStatusManager.updateStatus(RklSerialNumberStatusManager.STATUS_FAILED);

                } catch (Exception ignored) {
                }

                e.printStackTrace();
            }

        }).start();
    }

    //------------------------------------
    // RETRY
    //------------------------------------

    private boolean executeWithRetry(
            String name,
            Callable<Boolean> operation
    ) {

        for (int attempt = 1;
             attempt <= MAX_RETRY;
             attempt++) {

            ExecutorService executor =
                    Executors.newSingleThreadExecutor();

            try {

                Logger.section(
                        name
                                + " | TENTATIVA "
                                + attempt
                );

                UiBridge.setText(
                        "status",
                        name
                                + " tentativa "
                                + attempt
                );

                Future<Boolean> future =
                        executor.submit(
                                operation
                        );

                boolean success =
                        future.get(
                                TIMEOUT_SECONDS,
                                TimeUnit.SECONDS
                        );

                if (success) {

                    Logger.success(
                            name
                                    + " SUCCESS"
                    );

                    return true;

                }

            } catch (Exception e) {

                Logger.error(
                        name
                                + " - "
                                + e.getMessage()
                );

            } finally {

                executor.shutdown();
            }
        }

        return false;
    }
}

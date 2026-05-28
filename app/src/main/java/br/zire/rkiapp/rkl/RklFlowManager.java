package br.zire.rkiapp.rkl;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
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

public class RklFlowManager {

    private final RklConnectivityManager connectivityManager;
    private final RklAuthManager authManager;
    private final RklCertificateManager certificateManager;
    private final RklEphemeralCertificateManager ephemeralManager;
    private final RklIssuePosCertificateManager issueManager;
    private final RklLoadKbpkManager loadKbpkManager;
    private final RklLoadMkManager loadMkManager;
    private final RklLoadBdkManager loadBdkManager;
    private final RklSerialNumberStatusManager serialStatusManager;
    private final SerialNumberDatails serialNumberDatails;

    private static final int MAX_RETRY = 3;
    private static final int TIMEOUT_SECONDS = 5;

    public RklFlowManager(RklHttpClient httpClient) {

        connectivityManager = new RklConnectivityManager(httpClient);
        authManager = new RklAuthManager(httpClient);
        certificateManager = new RklCertificateManager(httpClient);
        ephemeralManager = new RklEphemeralCertificateManager(httpClient);
        issueManager = new RklIssuePosCertificateManager(httpClient);

        loadKbpkManager = new RklLoadKbpkManager(httpClient);
        loadMkManager = new RklLoadMkManager(httpClient);
        loadBdkManager = new RklLoadBdkManager(httpClient);

        serialStatusManager = new RklSerialNumberStatusManager(httpClient);
        serialNumberDatails = new SerialNumberDatails(httpClient);
    }

    public void startFlow() {

        new Thread(() -> {

            try {

                Logger.section("INICIANDO FLUXO RKL");

                RklSessionContext.resetSession();
                serialStatusManager.updateStatus(
                        RklSerialNumberStatusManager.STATUS_FAILED
                );

                RklSessionContext.transactionId =
                        RklEphemeralCertificateManager.generateTransactionId();

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

                serialNumberDatails.requestSerialNumberDetails();

                //------------------------------------
                // CERT CHAIN
                //------------------------------------

                certificateManager.requestCertificateChain();
                Thread.sleep(1000);

                //------------------------------------
                // KEYPAIR
                //------------------------------------

                KeyPair keyPair = RsaKeyManager.generateKeyIfNeeded();

                PublicKey publicKey = keyPair.getPublic();
                PrivateKey privateKey = keyPair.getPrivate();

                RklSessionContext.privateKey = privateKey;

                //------------------------------------
                // EPHEMERAL CERT
                //------------------------------------

                boolean ephemeralResponse =
                        ephemeralManager.requestEphemeralCertificate(MainActivity.context);

                String logPublic =
                        RsaKeyInspector.extractModulusFromPublicKey(
                                RklSessionContext.ephemeralPublicKey
                        );

                Logger.info("[FlowManager] Ephemeral PublicKey: " + logPublic);

                if (!ephemeralResponse) {
                    Logger.warning("Certificado efêmero não recebido");
                }

                //------------------------------------
                // CSR
                //------------------------------------

                String csr = RklCsrGenerator.generateCsrPem(
                        keyPair,
                        MainActivity.USN
                );

                if (csr == null) {
                    UiBridge.setText("status", "Falha ao gerar CSR");
                    Logger.error("CSR null");
                    return;
                }

                RklSessionContext.csr = csr;

                //------------------------------------
                // CERT ISSUE
                //------------------------------------

                issueManager.requestCertificateIssue();
                Thread.sleep(1000);

                //------------------------------------
                // STATUS EXECUTING
                //------------------------------------

                serialStatusManager.updateStatus(
                        RklSerialNumberStatusManager.STATUS_EXECUTING
                );

                //------------------------------------
                // LOAD KBPK (COM CONTROLE)
                //------------------------------------

                boolean kbpkOk = executeWithRetry(
                        "LOAD KBPK",
                        () -> loadKbpkManager.loadKbpk()
                );

                if (!kbpkOk) {
                    throw new IllegalStateException("Falha KBPK");
                }

                //------------------------------------
                // LOAD BDK E MK (COM PROFILE KEYS)
                //------------------------------------

                if (RklSessionContext.profileKeys == null || RklSessionContext.profileKeys.isEmpty()) {
                    throw new IllegalStateException("Nenhuma profile key carregada");
                }

                for (RklProfileKey profileKey : RklSessionContext.profileKeys) {

                    if (profileKey.isBdk()) {

                        Logger.section("PROCESSANDO BDK: " + profileKey.label);

                        boolean bdkOk = executeWithRetry(
                                "LOAD BDK",
                                () -> loadBdkManager.loadBdk(profileKey)
                        );

                        if (!bdkOk) {
                            throw new IllegalStateException("Falha BDK: " + profileKey.label);
                        }
                    }

                    if (profileKey.isMk()) {

                        Logger.section("PROCESSANDO MK: " + profileKey.label);

                        boolean mkOk = executeWithRetry(
                                "LOAD MK",
                                () -> loadMkManager.loadMk(profileKey)
                        );

                        if (!mkOk) {
                            throw new IllegalStateException("Falha MK: " + profileKey.label);
                        }
                    }
                }

                //------------------------------------
                // VALIDAÇÃO DE CHAVE
                //------------------------------------

                String before = RsaKeyInspector.extractModulusFromPublicKey(
                        RklSessionContext.ephemeralPublicKey
                );

                String after = RsaKeyInspector.extractModulusFromPublicKey(publicKey);

                if (!before.equals(after)) {
                    Logger.error("CRITICAL: PublicKey divergente");
                    throw new IllegalStateException("PublicKey inconsistente");
                }

                //------------------------------------
                // STATUS SUCCESS
                //------------------------------------

                serialStatusManager.updateStatus(
                        RklSerialNumberStatusManager.STATUS_SUCCESS
                );

                Logger.success("FLUXO RKI FINALIZADO");

            } catch (Exception e) {

                Logger.error("Erro no fluxo RKL");

                try {
                    serialStatusManager.updateStatus(
                            RklSerialNumberStatusManager.STATUS_FAILED
                    );
                } catch (Exception ex) {
                    Logger.error("Erro ao atualizar status");
                }

                e.printStackTrace();
            }

        }).start();
    }

    //------------------------------------
    // RETRY + TIMEOUT CORE
    //------------------------------------

    private boolean executeWithRetry(
            String name,
            Callable<Boolean> operation
    ) {

        for (int attempt = 1; attempt <= MAX_RETRY; attempt++) {

            ExecutorService executor = Executors.newSingleThreadExecutor();

            try {

                Logger.section(name + " | TENTATIVA " + attempt);

                UiBridge.setText(
                        "status",
                        name + " tentativa " + attempt
                );

                Future<Boolean> future = executor.submit(operation);

                boolean success = future.get(
                        TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                );

                if (success) {
                    Logger.success(name + " sucesso");
                    return true;
                }

                Logger.warning(name + " falhou tentativa " + attempt);

            } catch (Exception e) {

                Logger.error(name + " timeout/falha tentativa " + attempt);

                UiBridge.setText(
                        "status",
                        name + " falhou. Repetindo..."
                );

            } finally {
                executor.shutdownNow();
            }

            if (attempt < MAX_RETRY) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ignored) {}
            }
        }

        Logger.error(name + " falhou após 3 tentativas");

        return false;
    }

    //------------------------------------
    // UTIL
    //------------------------------------

    private String generateRandomHex(int length) {
        byte[] bytes = new byte[length / 2];
        new SecureRandom().nextBytes(bytes);

        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
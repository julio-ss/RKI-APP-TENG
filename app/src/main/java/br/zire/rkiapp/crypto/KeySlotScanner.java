package br.zire.rkiapp.crypto;

import static java.security.AccessController.getContext;

import com.pax.dal.IPed;
import com.pax.dal.entity.EPedKeyType;
import com.pax.dal.exceptions.PedDevException;

import java.util.HashSet;
import java.util.Set;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.rkl.RklLoadBdkManager;
import br.zire.rkiapp.rkl.RklLoadMkManager;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.util.HexUtil;
import br.zire.rkiapp.util.Logger;

public class KeySlotScanner {

    private static final int MAX_ATTEMPTS = 3;

    private static int mkAttempts = 0;
    private static int bdkAttempts = 0;

    private final IPed ped;
    private final RklHttpClient httpClient;

    public KeySlotScanner(IPed ped, RklHttpClient httpClient) {

        this.ped = ped;
        this.httpClient = httpClient;
    }

    public void scanAndInjectIfNeeded(
            String expectedKcv,
            String tr31,
            KeyType type
    ) {

        Logger.section("SCAN KEY SLOTS");

        boolean injectionPerformed = false;

        Set<String> deviceKcvs = new HashSet<>();

        //-----------------------------------------
        // VARREDURA COMPLETA
        //-----------------------------------------

        for (int index = 1; index <= 100; index++) {

            try {

                String deviceKcv = getKcv(index);

                if (deviceKcv != null) {

                    deviceKcvs.add(deviceKcv);

                    Logger.info(
                            "slot "
                                    + index
                                    + " kcv="
                                    + deviceKcv
                    );
                }

                //-----------------------------------------
                // SLOT VAZIO OU DIFERENTE
                //-----------------------------------------

                if (deviceKcv == null
                        || !deviceKcv.equalsIgnoreCase(expectedKcv)) {

                    Logger.info(
                            "injetando chave no índice "
                                    + index
                    );

                    inject(index, tr31, expectedKcv);

                    injectionPerformed = true;
                }

            } catch (Exception e) {

                Logger.warning(
                        "slot não suportado "
                                + index
                );
            }
        }

        //-----------------------------------------
        // CONTROLE DE LOOP
        //-----------------------------------------

        int attempts = getAttempts(type);

        if (!deviceKcvs.contains(expectedKcv)) {

            Logger.info("KCV ainda não estabilizado");

            incrementAttempts(type);

            restartCycle(type);

            return;
        }

        //-----------------------------------------

        if (!injectionPerformed) {

            incrementAttempts(type);

            Logger.info(
                    "nenhuma alteração detectada tentativa="
                            + attempts
            );

            if (attempts < MAX_ATTEMPTS) {

                restartCycle(type);

            } else {

                Logger.success(
                        "estado estabilizado após "
                                + attempts
                                + " tentativas"
                );

                resetAttempts(type);
            }

        } else {

            Logger.info(
                    "injeção realizada -> reiniciando ciclo"
            );

            resetAttempts(type);

            restartCycle(type);
        }
    }

    //-----------------------------------------

    private void inject(
            int index,
            String tr31,
            String expectedKcv
    ) {

        KeyInjectionManager manager =
                new KeyInjectionManager();

        manager.injectTr31(
                tr31,
                expectedKcv,
                (byte) index
        );
    }

    //-----------------------------------------

    private String getKcv(int index) {

        byte[] buffer = new byte[16];

        try {

            byte[] kcvBytes =
                    ped.getKCV(
                            EPedKeyType.AES_TMK,
                            (byte) index,
                            (byte) 3,
                            buffer
                    );

            if (kcvBytes == null)
                return null;

            String kcv =
                    HexUtil.bytesToHex(kcvBytes);

            return kcv.substring(0, 6);

        } catch (PedDevException e) {

            return null;
        }
    }

    //-----------------------------------------

    private void restartCycle(KeyType type) {

        Logger.info("reiniciando fluxo RKI");

        switch (type) {

            case MK:

                new RklLoadMkManager(httpClient)
                        .loadMk();

                break;

            case BDK:

                new RklLoadBdkManager(httpClient)
                        .loadBdk();

                break;
        }
    }

    //-----------------------------------------

    private int getAttempts(KeyType type) {

        return type == KeyType.MK
                ? mkAttempts
                : bdkAttempts;
    }

    private void incrementAttempts(KeyType type) {

        if (type == KeyType.MK)
            mkAttempts++;
        else
            bdkAttempts++;
    }

    private void resetAttempts(KeyType type) {

        if (type == KeyType.MK)
            mkAttempts = 0;
        else
            bdkAttempts = 0;
    }

    //-----------------------------------------

    public enum KeyType {

        MK,
        BDK
    }
}
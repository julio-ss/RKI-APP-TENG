package br.zire.rkiapp.util;

import android.os.Handler;
import android.os.Looper;
import android.widget.TextView;

import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;

public class UiBridge {

    private static final Handler mainHandler = new Handler(Looper.getMainLooper());

    // Guarda TextViews por chave (ex: "status", "log")
    private static final Map<String, WeakReference<TextView>> textViews = new HashMap<>();

    // Controle de animações ativas
    private static final Map<String, Boolean> animationFlags = new HashMap<>();

    // --------------------------------
    // REGISTRO
    // --------------------------------
    public static void registerTextView(String key, TextView textView) {
        textViews.put(key, new WeakReference<>(textView));
    }

    // --------------------------------
    // SET TEXTO (para animação automaticamente)
    // --------------------------------
    public static void setText(String key, String text) {
        stopAnimation(key);

        mainHandler.post(() -> {
            TextView tv = getTextView(key);
            if (tv != null) {
                tv.setText(text);
            }
        });
    }

    // --------------------------------
    // ANIMAÇÃO "Aguardando ..."
    // --------------------------------
    public static void startLoading(String key, String baseText, boolean loop) {
        stopAnimation(key);
        animationFlags.put(key, true);

        new Thread(() -> {
            int dots = 1;

            while (animationFlags.get(key) != null && animationFlags.get(key)) {

                int finalDots = dots;

                mainHandler.post(() -> {
                    TextView tv = getTextView(key);
                    if (tv != null) {
                        StringBuilder sb = new StringBuilder(baseText);
                        sb.append(" ");
                        for (int i = 0; i < finalDots; i++) {
                            sb.append(".");
                        }
                        tv.setText(sb.toString());
                    }
                });

                try {
                    Thread.sleep(500);
                } catch (InterruptedException ignored) {
                }

                dots++;
                if (dots > 3) {
                    if (loop) {
                        dots = 1;
                    } else {
                        break;
                    }
                }
            }
        }).start();
    }

    // --------------------------------
    // PARAR ANIMAÇÃO
    // --------------------------------
    public static void stopAnimation(String key) {
        animationFlags.put(key, false);
    }

    // --------------------------------
    // HELPER
    // --------------------------------
    private static TextView getTextView(String key) {
        WeakReference<TextView> ref = textViews.get(key);
        return ref != null ? ref.get() : null;
    }
}
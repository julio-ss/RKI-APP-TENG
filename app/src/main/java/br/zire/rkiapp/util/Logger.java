package br.zire.rkiapp.util;

import android.util.Log;
import android.widget.TextView;

public class Logger {

    private static final String TAG = "RKI_APP";

    private static TextView logView;

    public static void attachView(TextView view) {

        logView = view;

    }

    public static void section(String title) {

        String line = "====================================";

        write(line);
        write(title);
        write(line);

    }

    public static void info(String message) {

        write("• " + message);

    }

    public static void success(String message) {

        write("✓ " + message);

    }

    public static void warning(String message) {

        write("! " + message);

    }

    public static void error(String message) {

        write("✗ " + message);

    }

    private static void write(String message) {

        if(message == null) message = "null";

        Log.i(TAG, message);

        if(logView != null) {

            String finalMessage = message;
            logView.post(() -> {

                logView.append(finalMessage + "\n");

            });

        }

    }

}
package br.zire.rkiapp;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.pos.tectoy.deviceinfo.SPIDeviceInfo;
import com.pos.tectoy.sys.enums.ETermInfoKeySP;

import java.util.Map;

import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.rkl.RklFlowManager;
import br.zire.rkiapp.util.Logger;
import br.zire.rkiapp.util.USNValidator;
import br.zire.rkiapp.util.UiBridge;

public class MainActivity extends AppCompatActivity {

    public static Context context;
    private TextView retStatusConnect;
    private TextView tvLoading;
    private TextView terminalId;
    private ImageView helpButtonLoad;
    public static ProgressBar progressBar;

    private RklFlowManager flowManager;
    RklHttpClient httpClient;

    private HorizontalScrollView horizontalScroll;

    private final Handler handler = new Handler(Looper.getMainLooper());

    private int currentPage = 0;
    private int pageWidth = 0;

    private final int TOTAL_PAGES = 3;
    private final int INTERVAL_MS = 2000;

    public static String USN;
    public static String SN;
//    public static String SN_MOCK = "1180080231";
//    public static String USN = "F0012345678901234567890123";

    String getSn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);

            return insets;
        });

        context = getApplicationContext();
//        USN = getString(R.string.usn_default); //Regatando USN padrão - MOCK

        try {
            String str = null;
            SPIDeviceInfo spiDeviceInfo = SPIDeviceInfo.getInstance();

            Map<ETermInfoKeySP, String> infoTerminal = spiDeviceInfo.getTermInfoSP();
            str = infoTerminal.get(ETermInfoKeySP.SN);

            getSn = str;
            if (getSn == null || getSn.isEmpty()) {
                getSn = "UNKNOWN_SN";
            }
        } catch (Exception e) {
            Logger.error("Erro ao obter SN: " + e.getMessage());
            getSn = "UNKNOWN_SN";
        }
        SN = getSn;

        retStatusConnect = findViewById(R.id.retStatusConnect);
        tvLoading = findViewById(R.id.tvLoading);
        helpButtonLoad = findViewById(R.id.helpButtonLoad);
        progressBar = findViewById(R.id.progressBar);
        terminalId = findViewById(R.id.terminalId);
        horizontalScroll = findViewById(R.id.horizontalScroll);

        terminalId.setText(getSn);
//        String UsnLeftPed = USNValidator.formatToUSN(USN);
        USN = USNValidator.formatToUSN(SN);// Atribuindo SN ao USN
//        USN = USNValidator.formatToUSN("1180080231");// Atribuindo SN ao USN
//        USN = getSn;// Atribuindo SN ao USN*/--*


        horizontalScroll.post(() -> {
            pageWidth = horizontalScroll.getWidth();

            startAutoScroll();
        });

        UiBridge.registerTextView("status", tvLoading);
        UiBridge.registerTextView("log", retStatusConnect);

        UiBridge.startLoading("log", "Conectando", true);

        httpClient = new RklHttpClient();

        flowManager =
                new RklFlowManager(httpClient);

        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            flowManager.startFlow();
            progressBar.setIndeterminate(true);
        }, 2500);

        helpButtonLoad.setOnClickListener(v -> {
            flowManager.startFlow();
        });

    }

    private final Runnable autoScrollRunnable = new Runnable() {
        @Override
        public void run() {

            currentPage++;

            if (currentPage >= TOTAL_PAGES) {
                currentPage = 0;
            }

            int scrollX = currentPage * pageWidth;

            horizontalScroll.smoothScrollTo(scrollX, 0);

            handler.postDelayed(this, INTERVAL_MS);
        }
    };

    private void startAutoScroll() {
        handler.postDelayed(autoScrollRunnable, INTERVAL_MS);
    }

    private void stopAutoScroll() {
        handler.removeCallbacks(autoScrollRunnable);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        stopAutoScroll();
    }
}
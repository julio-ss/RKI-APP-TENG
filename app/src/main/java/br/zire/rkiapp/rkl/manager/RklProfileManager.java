package br.zire.rkiapp.rkl.manager;

import br.zire.rkiapp.MainActivity;
import br.zire.rkiapp.R;
import br.zire.rkiapp.network.RklHttpClient;
import br.zire.rkiapp.rkl.RklSessionContext;
import br.zire.rkiapp.rkl.model.RklProfile;
import br.zire.rkiapp.rkl.model.RklProfileKey;
import br.zire.rkiapp.rkl.parser.RklProfileParser;
import br.zire.rkiapp.util.Logger;

public class RklProfileManager {

    private final RklHttpClient httpClient;

    public RklProfileManager(RklHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public boolean loadProfile(int profileId) {

        try {

            Logger.section("LOAD PROFILE");

            String response = httpClient.get(
                    MainActivity.context.getString(R.string.profiles_endpoint)
                            + profileId
            );

            if (response == null || response.isEmpty()) {
                Logger.error("Profile vazio");
                return false;
            }

            RklProfile profile = RklProfileParser.parse(response);

            RklSessionContext.profile = profile;

            RklProfileKey mkKey = profile.getMkKey();
            RklProfileKey bdkKey = profile.getBdkKey();

            RklSessionContext.mkProfileKey = mkKey;
            RklSessionContext.bdkProfileKey = bdkKey;

            if (mkKey != null) {

                Logger.success("MK KEY OK");
                Logger.info("MK LABEL: " + mkKey.label);
                Logger.info("MK SLOT: " + mkKey.slotTargetPhy);
            }

            if (bdkKey != null) {

                Logger.success("BDK KEY OK");
                Logger.info("BDK LABEL: " + bdkKey.label);
                Logger.info("BDK SLOT: " + bdkKey.slotTargetPhy);
                Logger.info("DID ACTUAL: " + bdkKey.didActual);
            }

            return true;

        } catch (Exception e) {

            Logger.error("Erro profile: " + e.getMessage());
            return false;
        }
    }
}
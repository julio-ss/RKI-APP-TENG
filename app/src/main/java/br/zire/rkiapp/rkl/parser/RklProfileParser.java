package br.zire.rkiapp.rkl.parser;

import org.json.JSONArray;
import org.json.JSONObject;

import br.zire.rkiapp.rkl.model.RklProfile;
import br.zire.rkiapp.rkl.model.RklProfileKey;

public class RklProfileParser {

    public static RklProfile parse(String response) throws Exception {

        JSONObject json = new JSONObject(response);

        RklProfile profile = new RklProfile();

        profile.name = json.optString("name");
        profile.id = json.optInt("id");
        profile.totalKeys = json.optInt("totalKeys");

        JSONArray keys = json.optJSONArray("keys");

        if (keys == null) {
            return profile;
        }

        for (int i = 0; i < keys.length(); i++) {

            JSONObject item = keys.getJSONObject(i);

            RklProfileKey key = new RklProfileKey();

            key.keyId = item.optInt("Keyid");
            key.label = item.optString("label");
            key.keyFuncId = item.optInt("keyFuncId");
            key.keyTypeId = item.optInt("KeyTypeId");
            key.slotTargetPhy = item.optInt("slotTargetPhy");

            if (!item.isNull("didBegin")) {
                key.didBegin = item.optLong("didBegin");
            }

            if (!item.isNull("didEnd")) {
                key.didEnd = item.optLong("didEnd");
            }

            if (!item.isNull("didActual")) {
                key.didActual = item.optLong("didActual");
            }

            if (!item.isNull("ipekSize")) {
                key.ipekSize = item.optInt("ipekSize");
            }

            key.ksi = item.optString("ksi", "");
            key.kcv = item.optString("kcv", "");
            key.active = item.optBoolean("active");

            profile.keys.add(key);
        }

        return profile;
    }
}

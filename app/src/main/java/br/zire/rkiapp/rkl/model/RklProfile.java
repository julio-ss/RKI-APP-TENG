package br.zire.rkiapp.rkl.model;

import java.util.ArrayList;
import java.util.List;

public class RklProfile {

    public String name;
    public int id;
    public int totalKeys;

    public List<RklProfileKey> keys = new ArrayList<>();

    public RklProfileKey getMkKey() {

        for (RklProfileKey key : keys) {

            if (key.isMk()) {
                return key;
            }
        }

        return null;
    }

    public RklProfileKey getBdkKey() {

        for (RklProfileKey key : keys) {

            if (key.isDukpt()) {
                return key;
            }
        }

        return null;
    }
}

package br.zire.rkiapp.rkl.model;

public class RklProfileKey {

    public int keyId;
    public String label;
    public int keyFuncId;
    public int keyTypeId;
    public int slotTargetPhy;

    public Long didBegin;
    public Long didEnd;
    public Long didActual;

    public Integer ipekSize;

    public String ksi;
    public String kcv;

    public boolean active;

    public boolean isMk() {
        return keyFuncId == 1;
    }

    public boolean isDukpt() {
        return keyFuncId == 2;
    }
}
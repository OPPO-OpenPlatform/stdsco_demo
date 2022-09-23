package com.oplus.omes.stdsco.probe;

public interface ProbeCallBackListener {
    void onSuccess(String response);
    void onError(String err);
}

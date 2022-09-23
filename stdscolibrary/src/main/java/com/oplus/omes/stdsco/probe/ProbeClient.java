package com.oplus.omes.stdsco.probe;

import android.content.Context;

public class ProbeClient {
    public static native String getProbeRespStr(Object ctx);

    public static void startProbe(final Context ctx, final ProbeCallBackListener listener) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                String response = getProbeRespStr(ctx);
                if(listener==null){
                    return;
                }
                if(response != null){
                    listener.onSuccess(response);
                }else{
                    listener.onError("error");
                }
            }
        }).start();
    }
}

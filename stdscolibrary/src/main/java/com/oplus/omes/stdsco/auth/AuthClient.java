package com.oplus.omes.stdsco.auth;

import android.content.Context;
import android.text.TextUtils;

public class AuthClient {

    public static String APP_ID;
    private static volatile boolean inited = false;

    public static synchronized void init(Context context, String appId) {
        if (TextUtils.isEmpty(appId)) {
            throw new IllegalArgumentException("There are some arguments empty");
        }

        if (inited)
            return;
        inited = true;
        APP_ID = appId;
        nativeAuthInit(context, appId);
    }

    public static native void nativeAuthInit(Object context, String appId);
}

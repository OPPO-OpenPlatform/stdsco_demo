package com.oplus.omes.stdsco;

import android.content.Context;
import android.util.Log;

import com.oplus.omes.stdsco.auth.AuthClient;

public class StdScoMain {

    //是否进行过初始化
    private static volatile boolean inited = false;
    public static final String TAG = "StdSCO";

    public static synchronized void init(Context context, String appId) {
        if (inited)
            return;
        inited = true;
        long startTime=System.currentTimeMillis();
        Log.d(TAG,"------SDK库加载开始------ "+startTime);
        System.loadLibrary("omesStdSco");
        Log.d(TAG,"------SDK库加载完成 耗时："+(System.currentTimeMillis()-startTime)+"ms");

        startTime=System.currentTimeMillis();
        Log.d(TAG,"------鉴权初始化开始------ "+startTime);
        AuthClient.init(context, appId);
        Log.d(TAG,"------鉴权初始化完成 耗时："+(System.currentTimeMillis()-startTime)+"ms");

    }
}

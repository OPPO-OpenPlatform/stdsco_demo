package com.oplus.omes.stdsco;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.TextView;

import com.oplus.omes.stdsco.probe.ProbeClient;
import com.oplus.omes.stdsco.probe.ProbeCallBackListener;


public class ProbeActivity extends AppCompatActivity {

    public static final String TAG = "StdSCO";
    private TextView tv;
    private int count = 0;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_probe);
        tv = findViewById(R.id.textview);

        //获取系统检测结果
        getProbeResult();
    }

    private void getProbeResult() {
        long startTime=System.currentTimeMillis();
        Log.d(TAG,"------系统安全检测开始------ "+startTime);
        ProbeClient.startProbe(this, new ProbeCallBackListener() {
            @Override
            public void onSuccess(String response) {
                new Handler(Looper.getMainLooper()).post(
                        new Runnable() {
                            @Override
                            public void run() {
                                tv.setText(response + "\n" + "count:" + count++);
                                Log.d(TAG,"------系统安全检测完成 耗时："+(System.currentTimeMillis()-startTime)+"ms");
                            }
                        }
                );
            }

            @Override
            public void onError(String err) {

            }
        });
    }
}
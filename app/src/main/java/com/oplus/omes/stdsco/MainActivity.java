package com.oplus.omes.stdsco;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.Bundle;
import android.util.Log;
import android.view.View;

import java.util.List;

public class MainActivity extends AppCompatActivity {

    public static final String TAG = "StdSCO";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

            /*
              oppoSign：3bdce10cd69ecb9a419fdc04a2eeef98（开放平台创建应用时传入的签名信息）
              appid: 12024921（omesDemo）
              appkey:f24130ddd48949b3b59d01549ff344c3(勿外泄)
              appsecret:db458d587a134fddafde559803bd6868(勿外泄)
              测试环境后台使用固定的appSecret字段：d73704b7fa194cd9a36409b275dd75d1
              appserversecret:111cf15a1cfc44398d635a2777d8376f(勿外泄)
              */

        //初始化安全能力
        StdScoMain.init(this.getApplication(), "30624923");
    }

    public void onClickBtn1(View view)
    {
        listApp();
        Intent intent = new Intent(MainActivity.this, ProbeActivity.class);
        startActivity(intent);
    }

    public void onClickBtn2(View view)
    {
        Intent intent = new Intent(MainActivity.this, UrlCheckActivity.class);
        startActivity(intent);
    }

    public void onClickBtn3(View view)
    {
        Intent intent = new Intent(MainActivity.this, SafeLogActivity.class);
        startActivity(intent);
    }

    private void listApp() {
        List<ApplicationInfo> allApps = getPackageManager().getInstalledApplications(0);
        for(ApplicationInfo ai : allApps) {
            Log.d("SCORPION", "packageName:"+ai.packageName);
        }
    }
}
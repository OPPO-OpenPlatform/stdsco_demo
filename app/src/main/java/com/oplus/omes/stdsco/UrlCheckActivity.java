package com.oplus.omes.stdsco;

import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.View;


import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;
import com.google.android.material.textview.MaterialTextView;
import com.oplus.omes.stdsco.urlcheck.CheckListener;
import com.oplus.omes.stdsco.urlcheck.CheckResult;
import com.oplus.omes.stdsco.urlcheck.UrlCheckClient;

import java.util.ArrayList;
import java.util.List;


public class UrlCheckActivity extends AppCompatActivity {

    public static final String TAG = "StdSCO";
    private TextInputLayout til_url;
    private TextInputEditText tiet_url;
    private List<String> urls = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_urlcheck);
        til_url = (TextInputLayout) findViewById(R.id.til_url);
        tiet_url = (TextInputEditText) findViewById(R.id.tiet_url);
        tiet_url.addTextChangedListener(new TextWatcher() {
            @Override
            public void afterTextChanged(Editable editable) {

            }
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }
            @Override
            public void onTextChanged(CharSequence charSequence, int start, int before, int count) {
                String[] urlStrs = charSequence.toString().split("\\s+");
                if(urlStrs.length == 0){
                    til_url.setError("不正确的表达式");
                    til_url.setErrorEnabled(true);
                    return;
                }
                urls.clear();
                Log.v(TAG, "---------------");
                for(String url : urlStrs){
                    Log.v(TAG, "url:"+url);
                    urls.add(url);
                }
                til_url.setErrorEnabled(false);
            }
        });
    }

    public void onClickBtnCheck(View view) {
        long startTime=System.currentTimeMillis();
        Log.d(TAG,"------恶意URL检测开始------ "+startTime);
        UrlCheckClient.getInstance(this.getApplication()).checkUrls(urls, new CheckListener() {
            @Override
            public void onSuccess(List<CheckResult> results) {
                Log.i(TAG, "url check results : " + results);
                ((MaterialTextView)UrlCheckActivity.this.findViewById(R.id.mtv_result)).setText(results.toString());
                Log.d(TAG,"------恶意URL检测完成 耗时："+(System.currentTimeMillis()-startTime)+"ms");
            }
            @Override
            public void onFailure(int errorCode) {
                Log.i(TAG, "url check errno : " + errorCode);
                ((MaterialTextView)(UrlCheckActivity.this.findViewById(R.id.mtv_result))).setText("errorCode : " + errorCode);
                Log.d(TAG,"------恶意URL检测完成 耗时："+(System.currentTimeMillis()-startTime)+"ms");
            }
        });
    }
}
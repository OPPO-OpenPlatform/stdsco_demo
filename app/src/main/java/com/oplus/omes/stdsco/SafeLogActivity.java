package com.oplus.omes.stdsco;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Log;
import android.view.View;
import android.widget.RadioGroup;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.radiobutton.MaterialRadioButton;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;
import com.google.android.material.textview.MaterialTextView;
import com.oplus.omes.stdsco.safelog.StdScoLog;
import java.util.regex.Pattern;

public class SafeLogActivity extends AppCompatActivity {

    public static final String TAG = "StdSCO";
    private TextInputLayout til_tag;
    private TextInputEditText tiet_tag;
    private static int gIndex = -1;
    private static String gTag = "";
    private static volatile boolean isLogOpen = false;
    private static Handler gHandler;

    private static final String[] radioLevelStrs = {
            "LEVEL_NONE",
            "LEVEL_VERBOSE",
            "LEVEL_DEBUG",
            "LEVEL_INFO",
            "LEVEL_WARN",
            "LEVEL_ERROR",
            "LEVEL_ALL"
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_safelog);
        til_tag = (TextInputLayout) findViewById(R.id.til_tag);
        tiet_tag = (TextInputEditText) findViewById(R.id.tiet_tag);
        tiet_tag.addTextChangedListener(new TextWatcher() {
            @Override
            public void afterTextChanged(Editable editable) {

            }
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }
            @Override
            public void onTextChanged(CharSequence charSequence, int start, int before, int count) {
                if (TextUtils.isEmpty(charSequence) || isValidReg(charSequence.toString())) {
                    til_tag.setErrorEnabled(false);
                    return;
                }
                til_tag.setError("不正确的表达式");
                til_tag.setErrorEnabled(true);
            }
        });

        RadioGroup rg = (RadioGroup) findViewById(R.id.level_mode);
        rg.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener(){
            @Override
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                // TODO Auto-generated method stub
                int[] radioBtns = {
                        R.id.level_none,
                        R.id.level_verbose,
                        R.id.level_debug,
                        R.id.level_info,
                        R.id.level_warn,
                        R.id.level_error,
                        R.id.level_all
                };
                for(int i = 0; i < radioBtns.length; i++){
                    ((MaterialRadioButton)findViewById(radioBtns[i])).setChecked(false);
                }
                ((MaterialRadioButton)findViewById(checkedId)).setChecked(true);
            }
        });

        if(isLogOpen){
            ((MaterialButton) findViewById(R.id.materialButton1)).setText("日志打印已开启");
        }
        refreshCurrFilter();
    }

    private void refreshCurrFilter(){
        if(gIndex != -1) {
            ((MaterialButton) findViewById(R.id.materialButton2)).setText("日志过滤已开启");
            ((MaterialTextView) findViewById(R.id.currFilter)).setText(
                    String.format("级别：%s\n标签：%s", radioLevelStrs[gIndex], gTag));
        }
    }

    private boolean isValidReg(String pattern){
        try {
            Pattern r = Pattern.compile(pattern);
            if(r == null)
                return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public void printLog(){
        (gHandler = new Handler(Looper.getMainLooper())).postDelayed(new Runnable() {
            @Override
            public void run() {
                if(isLogOpen) {
                    Log.v("TagV", "A");
                    Log.d("TagD", "B");
                    Log.i("TagI", "C");
                    Log.w("TagW", "D");
                    Log.e("TagE", "E");
                    printLog();
                }
            }
        }, 3000);
    }

    public void onClickBtnPrint(View view) {
        isLogOpen = !isLogOpen;
        if(isLogOpen) {
            ((MaterialButton) view).setText("日志打印已开启");
            printLog();
        } else {
            ((MaterialButton) view).setText("日志打印已关闭");
            if(gHandler != null)
                gHandler.removeCallbacksAndMessages(null);
        }
    }

    public void onClickBtnFilter(View view) {
        int[] radioBtns = {
                R.id.level_none,
                R.id.level_verbose,
                R.id.level_debug,
                R.id.level_info,
                R.id.level_warn,
                R.id.level_error,
                R.id.level_all
        };
        int[] radioLevel = {
                StdScoLog.LEVEL_NONE,
                StdScoLog.LEVEL_VERBOSE,
                StdScoLog.LEVEL_DEBUG,
                StdScoLog.LEVEL_INFO,
                StdScoLog.LEVEL_WARN,
                StdScoLog.LEVEL_ERROR,
                StdScoLog.LEVEL_ALL
        };

        for(int i = 0; i < radioBtns.length; i++){
            if(((MaterialRadioButton)findViewById(radioBtns[i])).isChecked()){
                gIndex = i;
                break;
            }
        }
        gTag = tiet_tag.getText().toString();
        long startTime=System.currentTimeMillis();
        Log.d(TAG,"------安全日志设置开始------ "+startTime);
        StdScoLog.init(radioLevel[gIndex], gTag);
        Log.d(TAG,"------安全日志设置完成 耗时："+(System.currentTimeMillis()-startTime)+"ms");
        refreshCurrFilter();
    }
}
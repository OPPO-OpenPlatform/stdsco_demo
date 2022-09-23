package com.oplus.omes.stdsco.urlcheck;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class UrlCheckClient {
    private static volatile UrlCheckClient instance;
    private final ExecutorService executor;
    private final Cache cache;

    private UrlCheckClient(Context context){
        executor = Executors.newSingleThreadExecutor();
        cache = new Cache(context, "stdscourlcheck");
    }

    public static UrlCheckClient getInstance(Context context) {
        if(instance == null){
            synchronized (UrlCheckClient.class){
                if(instance == null){
                    instance = new UrlCheckClient(context);
                }
            }
        }
        return instance;
    }

    public void checkUrls(List<String> urls, CheckListener listener){
        if (urls == null) {
            if(listener != null)
                listener.onFailure(CheckListener.URL_CHECK_ERROR_PARAM_NULL);
            return;
        }

        int MAX_CHECK_COUNTS = 20;
        if (urls.size() > MAX_CHECK_COUNTS) {
            if(listener != null)
                listener.onFailure(CheckListener.URL_CHECK_ERROR_COUNT_LIMITED);
            return;
        }
        List<String> listUrls = new ArrayList<>(urls);
        executor.execute(() -> {
            List<CheckResult> results = new ArrayList<>();
            Iterator<String> iterator = listUrls.iterator();
            while (iterator.hasNext()){
                String url = iterator.next();
                CheckResult result = cache.get(url);
                if(result != null){
                    results.add(result);
                    iterator.remove();
                }
            }
            if(listUrls.isEmpty()){
                new Handler(Looper.getMainLooper()).post(() -> {
                    if(listener != null)
                        listener.onSuccess(results);
                });
                return;
            }
            try {
                JSONObject jsonReq = new JSONObject();
                JSONArray jsonArray = new JSONArray();
                for(int i = 0; i < listUrls.size(); i++){
                    String url =listUrls.get(i);
                    JSONObject jsonObject = new JSONObject();
                    jsonObject.put("id", i);
                    jsonObject.put("url", url);
                    jsonObject.put("deviceid", Math.abs(Cache.hashKeyForDisk(url).hashCode()) % 10 + "");
                    jsonArray.put(i, jsonObject);
                }
                jsonReq.put("urls", jsonArray);
                String resp = nativeUrlsCheck(jsonReq.toString());
                if(!TextUtils.isEmpty(resp)){
                    JSONObject jsonResp = new JSONObject(resp);
                    JSONArray jsonArray1 = jsonResp.getJSONArray("result");
                    for (int i = 0; i < jsonArray1.length(); i++) {
                        JSONObject jsonObject = (JSONObject) jsonArray1.get(i);
                        CheckResult result = new CheckResult();
                        result.setId(jsonObject.getInt("Id"));
                        result.setUrl(jsonObject.getString("Url"));
                        result.setUrlType(jsonObject.getInt("Urltype"));
                        result.setEvilClass(jsonObject.getInt("Evilclass"));
                        result.setTimestamp(System.currentTimeMillis());
                        cache.put(result);
                        results.add(result);
                    }
                    new Handler(Looper.getMainLooper()).post(() -> {
                        if(listener != null)
                            listener.onSuccess(results);
                    });
                }
            } catch (JSONException e) {
                e.printStackTrace();
                new Handler(Looper.getMainLooper()).post(() -> {
                    if(listener != null)
                        listener.onFailure(CheckListener.URL_CHECK_ERROR_EXCEPTION);
                });
            }
        });
    }

    public static native String nativeUrlsCheck(String content);
}

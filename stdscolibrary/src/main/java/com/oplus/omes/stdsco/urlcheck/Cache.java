package com.oplus.omes.stdsco.urlcheck;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Environment;

import com.oplus.omes.stdsco.urlcheck.LurCache.DiskLruCache;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Cache {
    private static final long CACHE_PERIOD = 36 * 60 * 60 * 1000L;
    private static final int CACHE_MAX_SIZE = 5 * 1024 * 1024;
    private DiskLruCache mDiskLruCache;

    public Cache(Context context, String uniqueName) {
        File cacheDir = getDiskCacheDir(context, uniqueName);
        if (!cacheDir.exists()) {
            cacheDir.mkdirs();
        }
        int appVer = getAppVersion(context);
        try {
            mDiskLruCache = DiskLruCache.open(cacheDir, appVer, 1, CACHE_MAX_SIZE);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private File getDiskCacheDir(Context context, String uniqueName) {

        String cachePath;

        if (Environment.MEDIA_MOUNTED.equals(Environment
                .getExternalStorageState())
                || !Environment.isExternalStorageRemovable()) {

            cachePath = context.getExternalCacheDir().getPath();
        } else {
            cachePath = context.getCacheDir().getPath();
        }

        return new File(cachePath + File.separator + uniqueName);
    }

    private int getAppVersion(Context context) {
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), 0);
            return info.versionCode;
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        return 1;
    }

    public static String hashKeyForDisk(String key) {
        String cacheKey;
        try {
            final MessageDigest mDigest = MessageDigest.getInstance("MD5");
            mDigest.update(key.getBytes());
            cacheKey = bytesToHexString(mDigest.digest());
        } catch (NoSuchAlgorithmException e) {
            cacheKey = String.valueOf(key.hashCode());
        }
        return cacheKey;
    }

    private static String bytesToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                sb.append('0');
            }
            sb.append(hex);
        }
        return sb.toString();
    }

    private void addDiskCache(String key, CheckResult result){
        DiskLruCache.Editor editor = null;
        try {
            editor = mDiskLruCache.edit(key);
            if (editor != null) {
                OutputStream outputStream = editor.newOutputStream(0);
                JSONObject jsonObject = new JSONObject();
                jsonObject.put("id", result.getId());
                jsonObject.put("url", result.getUrl());
                jsonObject.put("urlType", result.getUrlType());
                jsonObject.put("evilClass", result.getEvilClass());
                jsonObject.put("timestamp", result.getTimestamp());
                byte[] jsonBytes = jsonObject.toString().getBytes("UTF-8");
                outputStream.write(jsonBytes);
                editor.commit();
            }
            mDiskLruCache.flush();
        } catch (IOException | JSONException e) {
            e.printStackTrace();
            try {
                if(editor != null)
                    editor.abort();
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
        }
    }

    private byte[] _readStream(InputStream inStream) throws Exception {
        ByteArrayOutputStream outSteam = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = inStream.read(buffer)) != -1) {
            outSteam.write(buffer, 0, len);
        }
        outSteam.close();
        inStream.close();
        return outSteam.toByteArray();
    }

    private CheckResult getDiskCache(String key){
        DiskLruCache.Snapshot snapShot = null;
        try {
            snapShot = mDiskLruCache.get(key);
            if(snapShot != null){
                InputStream is = snapShot.getInputStream(0);
                String str = new String(_readStream(is), "UTF-8");
                JSONObject jsonObject = new JSONObject(str);
                CheckResult result = new CheckResult();
                result.setId(jsonObject.getInt("id"));
                result.setUrl(jsonObject.getString("url"));
                result.setUrlType(jsonObject.getInt("urlType"));
                result.setEvilClass(jsonObject.getInt("evilClass"));
                result.setTimestamp(jsonObject.getLong("timestamp"));
                snapShot.close();

                //判断缓存是否过期
                if(System.currentTimeMillis() < CACHE_PERIOD + result.getTimestamp()){
                    return result;
                } else {
                    mDiskLruCache.remove(key);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            if(snapShot != null){
                snapShot.close();
            }
        }
        return null;
    }

    public CheckResult get(String url){
        String key = hashKeyForDisk(url);
        return getDiskCache(key);
    }

    public void put(CheckResult result){
        String key = hashKeyForDisk(result.getUrl());
        addDiskCache(key, result);
    }
}

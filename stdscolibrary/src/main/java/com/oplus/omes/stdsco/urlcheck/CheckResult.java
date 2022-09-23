package com.oplus.omes.stdsco.urlcheck;

public class CheckResult {
    //请求中每个url的唯一编号，在一次请求中不可重复。
    private int id;

    //需要查询的URL。
    private String url;

    //标识url的安全状态，即网址的黑白灰（灰1 黑2 白3）状态。
    private int urlType;

    //恶意类型定义
    //1: 其他类型（暂无明确分类的其他恶意网址）
    //2: 欺诈诈骗（社工欺诈、信息诈骗、虚假销售等）
    //3: 恶意文件（病毒文件，木马文件，恶意apk文件的下载链接以及站点，挂马网站）
    //4: 博彩网站（博彩网站，在线赌博网站）
    //5: 色情网站（涉嫌传播色情内容，提供色情服务的网站）
    //6: 非法内容（根据法律法规不能传播的内容，主要为政治敏感内容）
    private int evilClass;

    //检测的时间戳
    private long timestamp;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public int getUrlType() {
        return urlType;
    }

    public void setUrlType(int urlType) {
        this.urlType = urlType;
    }

    public int getEvilClass() {
        return evilClass;
    }

    public void setEvilClass(int evilClass) {
        this.evilClass = evilClass;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    @Override
    public String toString() {
        return "{" +
                "id=" + id +
                ", url='" + url + '\'' +
                ", urlType=" + urlType +
                ", evilClass=" + evilClass +
                ", timestamp=" + timestamp +
                "}\n";
    }
}

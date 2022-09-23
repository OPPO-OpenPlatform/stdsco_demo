package com.oplus.omes.stdsco.safelog;

public class StdScoLog {

    //日志等级，与Android的原生Log对应
    public static final int LEVEL_VERBOSE = 2;
    public static final int LEVEL_DEBUG = 3;
    public static final int LEVEL_INFO = 4;
    public static final int LEVEL_WARN = 5;
    public static final int LEVEL_ERROR = 6;
    public static final int LEVEL_ASSERT = 7;
    public static final int LEVEL_ALL = Integer.MAX_VALUE;
    public static final int LEVEL_NONE = Integer.MIN_VALUE;

    /**
     * 初始化日志防泄漏功能
     * @param level 过滤日志的级别，低于此级别的日志将全部被过滤掉
     * @param tag 过滤日志的标签，空字串表示过滤所有标签的日志，否则只过滤正则匹配成功的标签的日志
     */
    public static synchronized void init(int level, String tag) {
        //tag为空则匹配所有
        if(tag == null || tag.equals(""))
            tag = "[\\s\\S]*";
        nativeLogInit(level, tag);
    }

    //本地方法，防泄漏的配置信息
    private static native void nativeLogInit(int level, String tag);
}
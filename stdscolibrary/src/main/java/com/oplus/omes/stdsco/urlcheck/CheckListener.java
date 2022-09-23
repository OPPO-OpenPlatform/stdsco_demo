package com.oplus.omes.stdsco.urlcheck;

import java.util.List;

public interface CheckListener {
    int URL_CHECK_ERROR_PARAM_NULL = -1; // 未完成初始化
    int URL_CHECK_ERROR_COUNT_LIMITED = -2; // 单次检测url数量超过阈值
    int URL_CHECK_ERROR_EXCEPTION = -3; // 检测频率超过阈值

    void onSuccess(List<CheckResult> results);
    void onFailure(int errorCode);
}

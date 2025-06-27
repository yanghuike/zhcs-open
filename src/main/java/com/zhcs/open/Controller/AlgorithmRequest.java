package com.zhcs.open.Controller;

import lombok.Data;

@Data
public class AlgorithmRequest {
    private Integer pageNo;
    private Integer pageSize;
    private AlgorithmParam param;

    @Data
    public static class AlgorithmParam {
        private String algorithmName;
        private String endTime;
        private String sceneType;
        private String startTime;
        private Integer status;
    }
} 
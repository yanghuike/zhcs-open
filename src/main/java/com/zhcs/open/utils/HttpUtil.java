package com.zhcs.open.utils;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class HttpUtil {
    
    /**
     * 发送GET请求
     * @param url 请求URL
     * @param headers 请求头
     * @return 响应内容
     */
    public static String doGet(String url, Map<String, String> headers) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet httpGet = new HttpGet(url);
            
            if (headers != null) {
                headers.forEach(httpGet::addHeader);
            }
            
            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                HttpEntity entity = response.getEntity();
                return entity != null ? EntityUtils.toString(entity, StandardCharsets.UTF_8) : null;
            }
        }
    }
    
    /**
     * 发送POST请求
     * @param url 请求URL
     * @param jsonBody JSON请求体
     * @param headers 请求头
     * @return 响应内容
     */
    public static String doPost(String url, String jsonBody, Map<String, String> headers) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost httpPost = new HttpPost(url);
            
            if (headers != null) {
                headers.forEach(httpPost::addHeader);
            }
            
            if (jsonBody != null) {
                StringEntity entity = new StringEntity(jsonBody, StandardCharsets.UTF_8);
                entity.setContentType("application/json");
                httpPost.setEntity(entity);
            }
            
            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                HttpEntity entity = response.getEntity();
                return entity != null ? EntityUtils.toString(entity, StandardCharsets.UTF_8) : null;
            }
        }
    }
} 
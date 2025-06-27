package com.zhcs.open.Controller;

import cn.hutool.http.HttpResponse;
import cn.hutool.http.HttpUtil;
import com.alibaba.fastjson.JSONObject;
import com.zhcs.open.config.Dept;
import com.zhcs.open.config.OpenApiProperties;
import com.zhcs.open.utils.Encrypt;
import com.zhcs.open.utils.TokenCache;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.HttpCookie;
import java.util.Objects;

@RestController
@RequestMapping("/resource")
public class ResourceController {

    @Autowired
    private OpenApiProperties properties;

/*    @Autowired
    private AuthorizeController authorizeController;*/

    @GetMapping("/getResource")
    public String getResource() throws Exception {
        Result result = getAuthToken();
        return HttpUtil.createGet(getUrl(properties.getResource().getNetworkStatusUrl()))
                .header("X-Subject-Token", result.getToken())
                .header("X-User-Role-Type", properties.getResource().getDefaultAuth().getRoleType())
                .execute()
                .body();
    }

    @GetMapping("/getDistrict")
    public String getDistrict(String code) throws Exception {
        Result result = getAuthToken();
        return HttpUtil.createGet(getUrl(properties.getResource().getDistrictUrl() + "/" + code))
                .header("X-Subject-Token", result.getToken())
                .header("X-User-Role-Type", properties.getResource().getDefaultAuth().getRoleType())
                .execute()
                .body();
    }

    @PostMapping("/getDept")
    public String getDept(@RequestBody Dept dept) throws Exception {
        Result result = getAuthToken();
        return HttpUtil.createPost(getUrl(properties.getResource().getDeptUrl()))
                .header("X-Subject-Token", result.getToken())
                .header("X-User-Role-Type", properties.getResource().getDefaultAuth().getRoleType())
                .body(JSONObject.toJSONString(dept))
                .execute()
                .body();
    }

    @PostMapping("/getAlgorithm")
    public String getAlgorithm(@RequestBody AlgorithmRequest algorithmRequest) throws Exception {
        Result result = getAuthToken();
        return HttpUtil.createPost(getUrl(properties.getResource().getAlgorithmUrl()))
                .header("X-Subject-Token", result.getToken())
                .header("X-User-Role-Type", properties.getResource().getDefaultAuth().getRoleType())
                .body(JSONObject.toJSONString(algorithmRequest))
                .execute()
                .body();
    }

    private Result getAuthToken() throws Exception {
        String username = properties.getResource().getDefaultAuth().getUsername();
        
        // 尝试从缓存获取token
        Result cachedResult = TokenCache.getToken(username);
        if (cachedResult != null) {
            return cachedResult;
        }

        // 缓存中没有或已过期，重新获取token
        AuthorizeRequest authorizeRequest = new AuthorizeRequest();
        authorizeRequest.setUserName(username);
        authorizeRequest.setPassword(properties.getResource().getDefaultAuth().getPassword());
        Result newResult = getToken(authorizeRequest);
        
        // 将新token存入缓存
        TokenCache.setToken(username, newResult);
        return newResult;
    }

    private String getUrl(String url) {
        return properties.getResourceServer().getPrefix() + url;
    }

    private Result getToken(AuthorizeRequest request) throws Exception {
        Result result = new Result();

        AuthorizeResponse authorizeResponse = firstLogin(request.getUserName());

        if (authorizeResponse.getRandomKey() == null || authorizeResponse.getRealm() == null || authorizeResponse.getEncryptType() == null) {
            throw new RuntimeException("获取登录信息失败");
        }
        request.setRandomKey(authorizeResponse.getRandomKey());
        request.setRealm(authorizeResponse.getRealm());
        request.setEncryptType(authorizeResponse.getEncryptType());

        String encodePassword = Encrypt.encrypt(
                request.getUserName() + ":" + properties.getAuth().getRealm() + ":" +
                        Encrypt.encrypt(request.getPassword(), properties.getAuth().getEncryptType()),
                authorizeResponse.getEncryptType()
        );

        String signature = Encrypt.encrypt(
                Encrypt.encrypt(request.getUserName() + ":" + properties.getAuth().getRealm() + ":" + encodePassword,
                        properties.getAuth().getEncryptType()) + ":" + authorizeResponse.getRandomKey(),
                properties.getAuth().getEncryptType()
        );

        JSONObject secondLoginJson = secondLogin(request.getUserName(), encodePassword, request.getRandomKey(), signature);
        if (secondLoginJson.getString("token") == null) {
            throw new RuntimeException("登录失败");
        }
        result.setUserName(request.getUserName());
        result.setUserCode(secondLoginJson.getString("userCode"));
        result.setToken(secondLoginJson.getString("token"));
        result.setLastLoginTime(secondLoginJson.getString("lastLoginTime"));

        return result;
    }

    private JSONObject secondLogin(String loginName, String password, String randomKey, String signature) {
        JSONObject json = new JSONObject();
        json.put("clientType", "winpc");
        json.put("realm", properties.getAuth().getRealm());
        json.put("encryptType", properties.getAuth().getEncryptType());
        json.put("userName", loginName);
        json.put("password", password);
        json.put("randomKey", randomKey);
        json.put("signature", signature);
        HttpResponse execute = HttpUtil.createPost(getUrls(properties.getAuth().getUrl())).body(json.toJSONString()).execute();
        String result = execute.body();
        return (JSONObject) JSONObject.parse(result);
    }

    /**
     * 加密字符串
     * @param str 待加密字符串
     * @param encryptType 加密类型
     * @return 加密后的字符串
     */
    public static String encrypt(String str, String encryptType) {
        if (StringUtils.isBlank(str)) {
            return str;
        }

        if ("MD5".equalsIgnoreCase(encryptType)) {
            return DigestUtils.md5Hex(str);
        }

        throw new IllegalArgumentException("Unsupported encrypt type: " + encryptType);
    }

    private AuthorizeResponse firstLogin(String loginName) throws IOException {
        JSONObject json = new JSONObject();
        json.put("clientType", "winpc");
        json.put("userName", loginName);
        String result = HttpUtil.createPost(getUrls(properties.getAuth().getUrl())).body(json.toJSONString()).execute().body();
        return JSONObject.parseObject(result, AuthorizeResponse.class);
    }

    private String getUrls(String url) {
        return properties.getServer().getPrefix() + url;
    }
}

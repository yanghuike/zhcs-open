package com.zhcs.open.Controller;

import cn.hutool.http.HttpResponse;
import cn.hutool.http.HttpUtil;
import com.alibaba.fastjson.JSONObject;
import com.zhcs.open.config.OpenApiProperties;
import com.zhcs.open.utils.Encrypt;
import javax.validation.Valid;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.HttpCookie;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Objects;

@Validated
@RestController
@RequestMapping("/Authorize")
public class AuthorizeController {

    @Autowired
    private OpenApiProperties properties;

    private static HttpCookie TGC = null;

    @PostMapping(path = "/getToken")
    public Result getToken(@RequestBody @Valid AuthorizeRequest request) throws Exception {
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
        HttpResponse execute = HttpUtil.createPost(getUrl(properties.getAuth().getUrl())).body(json.toJSONString()).execute();
        String result = execute.body();
        HttpCookie tgc = execute.getCookie("TGC");
        if (Objects.nonNull(tgc)) {
            TGC = tgc;
        }
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
        String result = HttpUtil.createPost(getUrl(properties.getAuth().getUrl())).body(json.toJSONString()).execute().body();
        return JSONObject.parseObject(result, AuthorizeResponse.class);
    }

    private String getUrl(String url) {
        return properties.getServer().getPrefix() + url;
    }

    @GetMapping("/selectCountByAppealType")
    public String selectCountByAppealType() {
        String token = getToken();
        return HttpUtil.createPost("http://10.6.146.44/sjzz-prod-api/sjzz/caseInfo/analysis/analysisByStatus?timeType=1")
                .header("authorization", "Bearer "+token)
                .header("cookie", "Admin-Token="+token)
                .execute().body();
    }


    @GetMapping("/analysisCountByAreaDeptHandle")
    public String analysisCountByAreaDeptHandle() {
        String token = getToken();
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");

        String endTime = simpleDateFormat.format(new java.util.Date());
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        LocalDate endDate = LocalDate.now().minusMonths(1);
        String beginTime = endDate.format(formatter);
        return HttpUtil.createPost("http://10.6.146.44/sjzz-prod-api/sjzz/caseInfo/analysis/analysisCountByAreaDeptHandle?beginTime="+beginTime+"&endTime="+endTime)
                .header("authorization", "Bearer "+token)
                .header("cookie", "Admin-Token="+token)
                .execute().body();
    }


    @GetMapping("/analysisCountByAreaStreetHandle")
    public String analysisCountByAreaStreetHandle() {
        String token = getToken();
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");

        String endTime = simpleDateFormat.format(new java.util.Date());
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        LocalDate endDate = LocalDate.now().minusMonths(1); // 减去一个月
        String beginTime = endDate.format(formatter);
        return HttpUtil.createPost("http://10.6.146.44/sjzz-prod-api/sjzz/caseInfo/analysis/analysisCountByAreaStreetHandle?beginTime="+beginTime+"&endTime="+endTime)
                .header("authorization", "Bearer "+token)
                .header("cookie", "Admin-Token="+token)
                .execute().body();
    }

    /**
     * 区县考核
     * @return
     */
    @GetMapping("/analysisScoreByDisposeUnitNameList")
    public String analysisScoreByDisposeUnitNameList() {
        String token = getToken();
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");

        String endTime = simpleDateFormat.format(new java.util.Date());
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        LocalDate endDate = LocalDate.now().minusMonths(1); // 减去一个月
        String beginTime = endDate.format(formatter);
        return HttpUtil.createPost("http://10.6.146.44/sjzz-prod-api/sjzz/caseInfo/analysis/analysisScoreByDisposeUnitNameList?beginTime="+beginTime+"&endTime="+endTime+"&reviewObjType=2")
                .header("authorization", "Bearer "+token)
                .header("cookie", "Admin-Token="+token)
                .execute().body();
    }

    /**
     * 市单位
     * @return
     */
    @GetMapping("/analysisScoreByDisposeUnitNameLists")
    public String analysisScoreByDisposeUnitNameLists() {
        String token = getToken();
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");

        String endTime = simpleDateFormat.format(new java.util.Date());
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        LocalDate endDate = LocalDate.now().minusMonths(1); // 减去一个月
        String beginTime = endDate.format(formatter);
        return HttpUtil.createPost("http://10.6.146.44/sjzz-prod-api/sjzz/caseInfo/analysis/analysisScoreByDisposeUnitNameList?beginTime="+beginTime+"&endTime="+endTime+"&reviewObjType=1")
                .header("authorization", "Bearer "+token)
                .header("cookie", "Admin-Token="+token)
                .execute().body();
    }

    /**
     * 市单位
     * @return
     */
    @GetMapping("/selectCountByChannelId")
    public String selectCountByChannelId() {
        String token = getToken();
        return HttpUtil.createPost("http://10.6.146.44/sjzz-prod-api/sjzz/caseInfo/analysis/selectCountByChannelId?timeType=1")
                .header("authorization", "Bearer "+token)
                .header("cookie", "Admin-Token="+token)
                .execute().body();
    }



    public String getToken() {
        JSONObject json = new JSONObject();
        json.put("enterSysName", "superAdminSjzz");
        json.put("enterSysPwd", "dnlkg+0wmS1p1HdQ8wcj/uSc2kDUAXnnTdeveFFu9PSQ4kI+OrwRh5OjK0CK61JyuRMm/15isRtaHVPB8+K0C4UV5F5Y3mBosPqnC+qUZZr8kWRmwR9bGwMqejG5zI4QzVq4wIVGAqedgA0GcN4PFH4I+UAP6ZQEST3ZYlT9im5RuinEGfoVzAOqFi45znrwL1TI7z4woS9Slz5gDWazZRTEsiLGKAPa+iO0fk7nI4rln/p3Ug47wnAiqmJs6JDrI9+iyn77XNg3mMwJnbe8s2lRr1IUGpWjlUqcpFKwoCSKrk1VlBDgs6xQdaNedT3i9PfIbWDGQm5ytTznySMohw==");
        String token = HttpUtil.createPost("http://10.6.146.44/sjzz-prod-api/login").body(json.toJSONString()).execute().body();
        Map map =JSONObject.parseObject(token, Map.class);

        return String.valueOf(map.get("token"));
    }

}

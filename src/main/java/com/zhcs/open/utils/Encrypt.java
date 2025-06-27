package com.zhcs.open.utils;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.commons.codec.digest.DigestUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * MD5加密
 */
public class Encrypt {

    private static final Logger logger = LoggerFactory.getLogger(Encrypt.class);

    public static final String CIPHER_ALGORITHM_ECB = "AES/ECB/PKCS5Padding";
    private static final Random rd = new Random();

    /**
     * 获得随机数
     *
     * <pre>
     * 0~999999999的值;
     * 不够位数补0
     * </pre>
     *
     * @return
     * @author 26007 - 2018年5月24日 上午11:44:56
     * @version 1.0.0
     */
    public static String getRandomKey() {
        return String.format("%08d", rd.nextInt(999999999));
    }

    /**
     * 加密
     *
     * @param inputText     输入字符
     * @param algorithmName 加密算法：MD5 SHA1
     * @param needRandom    是否需要添加随机数
     * @return
     * @throws Exception
     * @author 26007 - 2018年5月24日 上午10:47:16
     * @version 1.0.0
     */
    public static String encrypt(String inputText, String algorithmName, boolean needRandom) throws Exception {
        String randomKey = null;
        if (needRandom) {
            randomKey = getRandomKey();
        }

        return Encrypt.encrypt(inputText, algorithmName, randomKey);
    }

    /**
     * 加密
     *
     * @param inputText     输入字符
     * @param algorithmName 加密算法：MD5、SHA1
     * @param randomKey     随机参数
     * @return
     * @throws Exception
     * @author 26007 - 2018年5月24日 上午11:42:35
     * @version 1.0.0
     */
    public static String encrypt(String inputText, String algorithmName, String randomKey) throws Exception {
        if (StringUtils.isBlank(inputText)) {
            throw new IllegalArgumentException("Please enter inputText!");
        }
        if (StringUtils.isBlank(algorithmName) || "md5".equals(algorithmName.toLowerCase())) {
            algorithmName = "MD5";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithmName);
            digest.update(inputText.getBytes("UTF8"));

            if (StringUtils.isNotBlank(randomKey)) {
                digest.update(randomKey.getBytes());
            }

            byte encryptted[] = digest.digest();
            int i;
            StringBuffer encrypt = new StringBuffer();
            for (int offset = 0; offset < encryptted.length; offset++) {
                i = encryptted[offset];
                if (i < 0) {
                    i += 256;
                }
                if (i < 16) {
                    encrypt.append("0");
                }
                encrypt.append(Integer.toHexString(i));
            }
            return encrypt.toString();
        } catch (NoSuchAlgorithmException e) {
            throw e;
        } catch (UnsupportedEncodingException e) {
            throw e;
        }
    }

    /**
     * 加密
     *
     * @param inputText     输入字符串
     * @param algorithmName 加密算法：MD5、SHA1
     * @return
     * @throws Exception
     * @author 26007 - 2018年5月24日 上午10:48:15
     * @version 1.0.0
     */
    public static String encrypt(String inputText, String algorithmName) throws Exception {
        return Encrypt.encrypt(inputText, algorithmName, false);
    }

    /**
     * MD5加密,返回Base64
     */

    public static String md5Base64(String inputText, String algorithmName) {
        if (StringUtils.isBlank(inputText)) {
            throw new IllegalArgumentException("Please enter inputText!");
        }
        if (StringUtils.isBlank(algorithmName) || "md5".equals(algorithmName.toLowerCase())) {
            algorithmName = "MD5";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithmName);
            digest.update(inputText.getBytes("UTF8"));
            byte encryptted[] = digest.digest();
            byte[] baseCode = new Base64().encode(encryptted);
            return new String(baseCode, "UTF-8");
        } catch (NoSuchAlgorithmException e) {
            return "";
        } catch (UnsupportedEncodingException e) {
            return "";
        } catch (Exception e) {
            return "";
        }
    }

    public static String byte2hex(byte[] b) {
        StringBuilder hs = new StringBuilder();
        String stmp;
        for (int n = 0; b != null && n < b.length; n++) {
            stmp = Integer.toHexString(b[n] & 0XFF);
            if (stmp.length() == 1) {
                hs.append('0');
            }
            hs.append(stmp);
        }
        return hs.toString().toUpperCase();
    }

    /**
     * 将二进制转换成16进制
     *
     * @param buf
     * @return
     */
    public static String parseByte2HexStr(byte buf[]) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < buf.length; i++) {
            String hex = Integer.toHexString(buf[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            sb.append(hex.toUpperCase());
        }
        return sb.toString();
    }

    /**
     * 将16进制转换为二进制
     *
     * @param hexStr
     * @return
     */
    public static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1) {
            return null;
        }
        byte[] result = new byte[hexStr.length() / 2];
        for (int i = 0; i < hexStr.length() / 2; i++) {
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }

    /**
     * 数据库密码，MQ密码，redis密码的加密方式
     * AES-CBC模式加密
     *
     * @param encryPassword
     * @param aesKey
     * @return
     */
    public static String encryptByAesCbc(String encryPassword, String aesKey, String aesIve, Boolean isHex) {

        if (StringUtils.isEmpty(encryPassword)) {
            logger.info("the encryPassword is null,will return null");
            return null;
        }

        if (StringUtils.isEmpty(encryPassword) || StringUtils.isEmpty(aesKey) || StringUtils.isEmpty(aesIve)) {

            logger.info("the encryPassword is null,will return null");
            return null;
        }

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] raw = null;
            if (isHex) {
                raw = parseHexStr2Byte(aesKey);
            } else {
                raw = aesKey.getBytes();
            }
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            IvParameterSpec iv = new IvParameterSpec(aesIve.getBytes());// 使用CBC模式，需要一个向量iv，可增加加密算法的强度
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            byte[] encrypted = cipher.doFinal(encryPassword.getBytes("UTF-8"));
            return parseByte2HexStr(encrypted);
        } catch (Exception e) {
            logger.error("ecrypt pass error by AES-CBC", e);
        }
        return null;
    }

    /**
     * 数据库密码，MQ密码，redis密码的解密方式
     * AES-CBC模式解密
     *
     * @param encryPassword
     * @param aesKey
     * @return
     */
    public static String decryptByAesCbc(String encryPassword, String aesKey, String aesIve, Boolean isHex) {

        if (StringUtils.isEmpty(encryPassword)) {
            logger.info("the encryPassword is null,will return null");
            return null;
        }

        if (StringUtils.isEmpty(encryPassword) || StringUtils.isEmpty(aesKey) || StringUtils.isEmpty(aesIve)) {
            logger.info("the encryPassword is null,will return null");
            return null;
        }

        try {
            byte[] raw;
            if (isHex) {
                raw = parseHexStr2Byte(aesKey);
            } else {
                raw = aesKey.getBytes();
            }
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec(aesIve.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] encrypted1 = parseHexStr2Byte(encryPassword);
            byte[] originalPassByte = cipher.doFinal(encrypted1);
            return new String(originalPassByte, "UTF-8");
        } catch (Exception e) {
            logger.error("decrypt pass error by AES-CBC", e);
        }
        return null;
    }

    public static String getEncryPass(String pass, String name, String type) {
        try {
            String tem1 = encrypt(pass, "MD5");
            String tem2 = name + tem1;
            String tem3 = encrypt(tem2, "MD5");
            String tem4 = encrypt(tem3, "MD5");
            return tem4;
        } catch (Exception e) {
            logger.error("createSalt error : ", e);
        }
        return null;
    }

    public static String getSignature(String name, String md5Salt, String pass, String random_key, String type, String defaltSalt) {
        try {
            //如果盐值不等于默认值"TheNextService"，则表示密码已经经过tem1的加密
            if (defaltSalt.equals(md5Salt)) {
                String tem1 = name + ":" + md5Salt + ":" + pass;
                pass = encrypt(tem1, "MD5");
            }
            String tem3 = pass + ":" + random_key;
            String tem4 = encrypt(tem3, "MD5");
            return tem4;
        } catch (Exception e) {
            logger.error("createSalt error : ", e);
        }
        return null;
    }


    /**
     * 安全基线要求，动态生成AES秘钥
     *
     * @return
     */
    public static String createAesKey(String key, String salt) {
        try {
            if (StringUtils.isBlank(salt) || StringUtils.isBlank(key)) {
                return null;
            }
            int iterCount = 1000;
            PBEKeySpec spec = new PBEKeySpec(key.toCharArray(), parseHexStr2Byte(salt), iterCount, 256);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey secretKey = skf.generateSecret(spec);
            byte[] keyByte = secretKey.getEncoded();
            String aesKey = parseByte2HexStr(keyByte);
            return aesKey;
        } catch (Exception e) {
            logger.error("createAesKey error : ", e);
        }
        return null;
    }

    /**
     * 安全基线要求，生成随机盐值，并入库
     *
     * @return
     */
    public static String createSalt(int len) {
        try {
            if (len > 0 && len < 1024) {
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                byte[] salt = new byte[len];
                random.nextBytes(salt);
                String saltStr = parseByte2HexStr(salt);
                return saltStr;
            }
        } catch (Exception e) {
            logger.error("createSalt error : ", e);
        }
        return null;
    }



}

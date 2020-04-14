package pers.alex.utils.rsa.rsa;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA加解密（前后端支持版本）
 *      支持2048位RSA密钥对
 *
 *      前端需要使用RSA公钥（Base64编码）进行加密
 *      后端使用RSA私钥（这里可以是PrivateKey或者Base64编码格式）进行解密
 *
 * @author Alex
 * @date 4/13/2020 9:55 AM
 */
public class RSAUtil {

    private static Cipher cipher;

    private static final String KEY_TYPE = "RSA";

    private static final int KEY_SIZE = 2048;

    static{
        try {
            cipher = Cipher.getInstance(KEY_TYPE);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成密钥对
     * @return
     */
    public static KeyPair generateKeyPair(){
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_TYPE);
            // 密钥位数
            keyPairGen.initialize(KEY_SIZE);
            // 密钥对
            return keyPairGen.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 产生密钥对，并且导出密钥对
     * @param filePath
     * @return
     */
    public static KeyPair generateKeyPair(String filePath){
        try {
            // 密钥对
            KeyPair keyPair = generateKeyPair();
            // 公钥
            PublicKey publicKey = keyPair.getPublic();
            // 私钥
            PrivateKey privateKey = keyPair.getPrivate();
            //得到公钥字符串
            String publicKeyString = getKeyString(publicKey);
            //得到私钥字符串
            String privateKeyString = getKeyString(privateKey);
            //将密钥对写入到文件
            FileWriter pubfw = new FileWriter(filePath + "/publicKey.keystore");
            FileWriter prifw = new FileWriter(filePath + "/privateKey.keystore");
            BufferedWriter pubbw = new BufferedWriter(pubfw);
            BufferedWriter pribw = new BufferedWriter(prifw);
            pubbw.write(publicKeyString);
            pribw.write(privateKeyString);
            pubbw.flush();
            pubbw.close();
            pubfw.close();
            pribw.flush();
            pribw.close();
            prifw.close();
            //将生成的密钥对返回
            return keyPair;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 得到密钥字符串
     * @param key
     * @return  密钥字符串（Base64编码后）
     * @throws Exception
     */
    public static String getKeyString(Key key) {
        byte[] keyBytes = key.getEncoded();
        return (new BASE64Encoder()).encode(keyBytes);
    }

    /**
     * 得到公钥
     * Base64编码公钥和PublicKey的转换
     * @param key Base64编码后的公钥字符串
     * @return
     * @throws Exception
     */
    public static PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_TYPE);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * 得到私钥
     * Base64编码私钥和PrivateKey的转换
     * @param key Base64编码后的私钥字符串
     * @return
     * @throws Exception
     */
    public static PrivateKey getPrivateKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_TYPE);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 公钥加密
     * @param publicKey 公钥（Base64编码）
     * @param plainText 明文
     * @return 密文
     */
    public static String encrypt(String publicKey, String plainText){
        try {
            return encrypt(getPublicKey(publicKey), plainText);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 公钥加密
     * @param publicKey 公钥
     * @param plainText 明文
     * @return 密文
     */
    public static String encrypt(PublicKey publicKey, String plainText) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            byte[] enBytes = cipher.doFinal(plainText.getBytes());
            return (new BASE64Encoder()).encode(enBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 私钥解密
     * @param privateKey 私钥（Base64编码）
     * @param enStr 密文
     * @return 明文
     */
    public static String decrypt(String privateKey, String enStr){
        try {
            return decrypt(getPrivateKey(privateKey), enStr);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 私钥解密
     * @param privateKey 私钥
     * @param enStr 密文
     * @return  明文
     */
    public static String decrypt(PrivateKey privateKey, String enStr) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] deBytes = cipher.doFinal((new BASE64Decoder()).decodeBuffer(enStr));
            return new String(deBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }



    public static void main(String[] args) {

        //生成密钥对
        KeyPair keyPair = generateKeyPair();

        //获取公私钥
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println(publicKey);
        System.out.println(privateKey);

        //明文
        String source = "高可用架构对于互联网服务基本是标配。";

        System.out.println("\n\n\n*******************************************************************************\n\n\n");

        //使用公私钥进行加解密
        String aData = encrypt(publicKey, source);
        String dData = decrypt(privateKey, aData);
        System.out.println("加密后文字：\r\n" + aData);
        System.out.println("解密后文字: \r\n" + dData);

        System.out.println("\n\n\n*******************************************************************************\n\n\n");

        //使用Base编码的密钥进行加解密 （前后端时使用）
        try {
            String pubKeyStr = getKeyString(publicKey);
            String priKeyStr = getKeyString(privateKey);
            System.out.println("PublicKey: \r\n" + pubKeyStr);
            System.out.println("PrivateKey: \r\n" + priKeyStr);
            String aData1 = encrypt(pubKeyStr, source);
            String dData1 = decrypt(priKeyStr, aData1);
            System.out.println("加密后文字：\r\n" + aData1);
            System.out.println("解密后文字: \r\n" + dData1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}

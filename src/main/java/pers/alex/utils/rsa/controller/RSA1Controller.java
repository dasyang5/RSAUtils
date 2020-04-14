package pers.alex.utils.rsa.controller;

import com.alibaba.fastjson.JSONObject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import pers.alex.utils.rsa.rsa1.RSASessionUtil;
import pers.alex.utils.rsa.rsa1.RSAUtil;

import javax.servlet.http.HttpServletRequest;
import java.security.PrivateKey;

/**
 * @author Alex
 * @date 4/13/2020 4:50 PM
 */
@Controller
@RequestMapping("/rsa1")
public class RSA1Controller {

    @RequestMapping("/")
    public String toDemo1() {
        return "/demo1";
    }

    /**
     * 返回公钥
     * @param request
     * @return
     */
    @RequestMapping("/getPublicKey")
    @ResponseBody
    public JSONObject getPublicKey(HttpServletRequest request) {

        return new JSONObject()
                .fluentPut("code", 0)
                .fluentPut("publicKey", RSASessionUtil.getPublicKey(request.getSession()));

    }

    @RequestMapping("/login")
    @ResponseBody
    public JSONObject login(HttpServletRequest request,
                            String userName, String password) {

        PrivateKey privateKey = RSASessionUtil.getPrivateKey(request.getSession());

        try {

            userName = RSAUtil.decrypt(privateKey, userName);

            password = RSAUtil.decrypt(privateKey, password);

            return new JSONObject().fluentPut("code", 0);

        } catch (Exception e) {

            return new JSONObject().fluentPut("code", 1);

        }

    }

}

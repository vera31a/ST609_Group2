package com.ruoyi.web.controller.system;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.ruoyi.common.core.controller.BaseController;
import com.ruoyi.common.core.domain.AjaxResult;
import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.utils.poi.ExcelUtil;
import com.ruoyi.web.core.config.ECCCoder;

import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.AsymmetricCrypto;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;
import cn.hutool.crypto.symmetric.SymmetricCrypto;

/**
 * 图片验证码（支持算术形式）
 * 
 * @author ruoyi
 */
@Controller
@RequestMapping("/system/jm")
public class JamiController extends BaseController
{
	 private String prefix = "system/jm";
	 
	    @GetMapping()
	    public String user()
	    {
	        return prefix + "/jm";
	    }
	    
	    @PostMapping("jiami")
	    @ResponseBody
	    public AjaxResult jiami(String type,String mKey,String jia){
	    	
	    	if (type.equals("AES")) {
	    		SymmetricCrypto aes = new SymmetricCrypto(SymmetricAlgorithm.AES, mKey.getBytes());
	    		//加密为16进制表示
	    		String encryptHex = aes.encryptHex(jia);
	    		return AjaxResult.success("成功",encryptHex);
			}
	    	if (type.equals("DES")) {
	    		SymmetricCrypto aes = new SymmetricCrypto(SymmetricAlgorithm.DES, mKey.getBytes());
	    		//加密为16进制表示
	    		String encryptHex = aes.encryptHex(jia);
	    		return AjaxResult.success("成功",encryptHex);
			}
	    	if (type.equals("RSA")) {
	    		RSA rsa = new RSA();

	    		//获得私钥
	    		String privateKeyBase64 = rsa.getPrivateKeyBase64();
	    		//获得公钥
	    		String publicKeyBase64 = rsa.getPublicKeyBase64();
	    		
	    		byte[] encrypt = rsa.encrypt(StrUtil.bytes(jia, CharsetUtil.CHARSET_UTF_8), KeyType.PublicKey);
	    		String encodeHexStr = HexUtil.encodeHexStr(encrypt);
	    		
	    		Map<String, Object> cmap = new HashMap<>();
	    		cmap.put("sKey", privateKeyBase64);
	    		cmap.put("gKey", publicKeyBase64);
	    		cmap.put("data", encodeHexStr);
	    		
	    		return AjaxResult.success("成功",cmap);
	    	}
	    	if (type.equals("ECC")) {
	    	     Map<String, Object> keyMap;
				try {
					keyMap = ECCCoder.initKey();
					   String publicKey = ECCCoder.getPublicKey(keyMap);  
		    	        String privateKey = ECCCoder.getPrivateKey(keyMap);  
		    	        System.err.println("公钥: \n" + publicKey);  
		    	        System.err.println("私钥： \n" + privateKey);  
		    	        
		    	        byte[] encodedData = ECCCoder.encrypt(StrUtil.bytes(jia, CharsetUtil.CHARSET_UTF_8), publicKey);
		    	        String encodeHexStr = HexUtil.encodeHexStr(encodedData);
		    	        Map<String, Object> cmap = new HashMap<>();
			    		cmap.put("sKey", privateKey);
			    		cmap.put("gKey", publicKey);
			    		cmap.put("data", encodeHexStr);
			    		return AjaxResult.success("成功",cmap);
				} catch (Exception e) {
					e.printStackTrace();
					return AjaxResult.error(e.getMessage());
				}  
	    	     
	    	     
	    	        
	    	        
	    	
	    	}
	    	
	    
	    return AjaxResult.success();
	    }
	    
	    @PostMapping("jiemi")
	    @ResponseBody
	    public AjaxResult jiemi(@RequestBody Jia jia){
	    	
	    	String  type = jia.getType();
	    	String jie = jia.getJie();
	    	String sKey = jia.getsKey();
	    	String mKey = jia.getmKey();
			if (type .equals("AES")) {
	    		SymmetricCrypto aes = new SymmetricCrypto(SymmetricAlgorithm.AES, mKey.getBytes());
	    		//加密为16进制表示
	    		String decryptStr = aes.decryptStr(jie, CharsetUtil.CHARSET_UTF_8);
	    		return AjaxResult.success("成功",decryptStr);
			}
	    	if (type.equals("DES")) {
	    		SymmetricCrypto aes = new SymmetricCrypto(SymmetricAlgorithm.DES, mKey.getBytes());
	    		//加密为16进制表示
	    		String decryptStr = aes.decryptStr(jie, CharsetUtil.CHARSET_UTF_8);
	    		return AjaxResult.success("成功",decryptStr);
			}
	    	if (type.equals("RSA")) {
	    	//	sKey = sKey.replace(" ", "");
	    		RSA rsa = new RSA(sKey, null);
	    		byte[] aByte = HexUtil.decodeHex(jie);	    		
	    		byte[] decrypt = rsa.decrypt(aByte, KeyType.PrivateKey);
	    		return AjaxResult.success("成功",new String(decrypt));
	    	}
	    	if (type.equals("ECC")) {
		    	//	sKey = sKey.replace(" ", "");
		    		byte[] aByte = HexUtil.decodeHex(jie);	    
		    		
		    		 try {
						Map<String, Object> keyMap = ECCCoder.initKey();
						 byte[] decodedData = ECCCoder.decrypt(aByte, sKey);  
				    		return AjaxResult.success("成功",new String(decodedData));
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
						return AjaxResult.error(e.getMessage());
					}  
		    		
		    	}
	    
	    return AjaxResult.success();
	    }
	    
	    
	    public static void main(String[] args) {
	    	
//	    	AsymmetricCrypto asymmetricCrypto = new AsymmetricCrypto("EC");
//	    	String privateKeyBase64 = asymmetricCrypto.getPrivateKeyBase64();
//	    	String publicKeyBase64 = asymmetricCrypto.getPublicKeyBase64();
//	    	String a = "2324324234";
//	    	byte[] decrypt = asymmetricCrypto.decrypt(StrUtil.bytes(a, CharsetUtil.CHARSET_UTF_8), KeyType.PrivateKey);
//	    	sys
////	  
//	    	String PRIVATE_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIJkgW4pS06OuPJtiu4xv4x5ynogYubZYi/04afDVZFFjV4qbAdBWhrT+mSRIhN3vAs+XIhFeuwnlUtD5WRGof0aRZWIp4f8BBD3o6mOLMZij1rpTkWShqsaTF8VUDmMD2BsgJVBUq/JRSVcznsERW2PXhOfNMg+WQSg/JPZ00M9AgMBAAECgYBcgrQ1lUShoq7jCQcVweP15X7bMNkakcaQ4bury/GMlP0cfxqP9zTXbefrq/CyQTQAAimiYTE6FUdd0/kPMPHB0fVtrsqwnJqPVbD9d6ROaWfkxS0NdRlFqLqfq3Lq2oaJR91TnPmDHkdCWmJs5OMcT2MNOf+MY/p3cgC+vwc63QJBAPnL4LEkgf5Ajc+3oCAUeQIvi3Yc12YGqrdDI3grP+sQZzKqw6jM+bI2pXrVfiw9edwND5GEoijSNwk8toVSH5cCQQCFoX+RMjEIkKUsqoovAYknXcF4dSGAC6OjJhSpD6TtIImcjLYEE3pU/nlxZewruUHoGRGXf26R1IwVPv5IfE5LAkEAmdlD7lZ56cqAjSqfaKKzVPFLh9eDoscAZhbnxZ99op1bsg0SrOhx8Z1OljTfnQfQAgPZTtrNtS6jzwChucM2yQJAYgJgMNsSMYj9THRMY0uKD7BpDPNDvclLnIZ6ksChozXBGGvvt6+dgqcd5Tju7eazWwq/51CUhSrSD2cjU4CwXwJAOAmFJHyeCvZ+oQerLkr/3pP1+uBBVd3R1BL5jhR+otMxUsSx0L1Q36nJC3Hr3VPZicaRzxOWd167bhEPoqUWgQ==";
//
//	    	RSA rsa = new RSA(PRIVATE_KEY, null);
//
//	    	String a = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIJkgW4pS06OuPJtiu4xv4x5ynogYubZYi/04afDVZFFjV4qbAdBWhrT+mSRIhN3vAs+XIhFeuwnlUtD5WRGof0aRZWIp4f8BBD3o6mOLMZij1rpTkWShqsaTF8VUDmMD2BsgJVBUq/JRSVcznsERW2PXhOfNMg+WQSg/JPZ00M9AgMBAAECgYBcgrQ1lUShoq7jCQcVweP15X7bMNkakcaQ4bury/GMlP0cfxqP9zTXbefrq/CyQTQAAimiYTE6FUdd0/kPMPHB0fVtrsqwnJqPVbD9d6ROaWfkxS0NdRlFqLqfq3Lq2oaJR91TnPmDHkdCWmJs5OMcT2MNOf+MY/p3cgC+vwc63QJBAPnL4LEkgf5Ajc+3oCAUeQIvi3Yc12YGqrdDI3grP+sQZzKqw6jM+bI2pXrVfiw9edwND5GEoijSNwk8toVSH5cCQQCFoX+RMjEIkKUsqoovAYknXcF4dSGAC6OjJhSpD6TtIImcjLYEE3pU/nlxZewruUHoGRGXf26R1IwVPv5IfE5LAkEAmdlD7lZ56cqAjSqfaKKzVPFLh9eDoscAZhbnxZ99op1bsg0SrOhx8Z1OljTfnQfQAgPZTtrNtS6jzwChucM2yQJAYgJgMNsSMYj9THRMY0uKD7BpDPNDvclLnIZ6ksChozXBGGvvt6+dgqcd5Tju7eazWwq/51CUhSrSD2cjU4CwXwJAOAmFJHyeCvZ+oQerLkr/3pP1+uBBVd3R1BL5jhR+otMxUsSx0L1Q36nJC3Hr3VPZicaRzxOWd167bhEPoqUWgQ==";
//
//	    	byte[] aByte = HexUtil.decodeHex(a);
//	    	byte[] decrypt = rsa.decrypt(aByte, KeyType.PrivateKey);
//	    	System.err.println(new String(decrypt));
	    	
//	    String PRIVATE_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKamDevew5iP9WkZ8kxvfNZ4+nGTUcGgkGqKrVwSQfkmEu3MqwmOzo7u2M09G/pAlUfyv4VYwb6isovWmLi3z0HENVZn0rOnf4QVZ6thqSayoaAXmNoVAnwb0xxV0uPyyBEOj8JYRArTo9l/ZiIld2vVZ36S4qIyAv/qXQVGVg/9AgMBAAECgYBRyYVjkXylT2G+J0HHSaAXEmC3hPnG8apu34ide0htosX/d0cp9bBibc5xS+CDPVcGbJiaNSlBClBeWP+zCGLqtUdeYbI+O/uYJq1dhS3Yuo22dPR0xzMEcZFkLl3l0iIkCUY39Biszthr1W2hrFU6Wa53NuDr8wHTGH/ayAk+gQJBAM7LGvT9O6o+Xk03x6IwOIpswazsUT5iNZjbDNs45EoYSS3Nap39ANgAcW3GFg7b/uJygaTlWi2Kqp3vBRN6nwkCQQDOTYSiCvyq4MbDRaoaXyCVWwh717krYJrHb3dtmHgQyxyBQzVbdl+ISJ5N2UwIaql6xDTzp7680rOEYBgDc7JVAkBjXm3Bs73r/LRL3rXrVciVm9UlRxlzJLYkkX4ICbqJcEoZ3E+TQ3QYV34qBbmrwkMkhWmO1zcSE0QRSD3kMlQhAkEAmi4e6MfTS5XPllKzLSBZBqZRMdToQ33gTxqEI/kmCk7xz7093EwcW4sCHGZAx62HWgPXGx4Lk6zYkx8J81J9PQJAZ13EaZVqloDw6IpPRTMoQZaZ76p1bqDLZwfwFR3OXl2RbC2S+3zHySw0RzAGYvsi64YtE/QgSyW9wLYbDduDfA==";
//	    String PRIVATE_KEY = "45555555554353453453453455";
//    	
//	    	
//	    	String Pub_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmpg3r3sOYj/VpGfJMb3zWePpxk1HBoJBqiq1cEkH5JhLtzKsJjs6O7tjNPRv6QJVH8r+FWMG+orKL1pi4t89BxDVWZ9Kzp3+EFWerYakmsqGgF5jaFQJ8G9McVdLj8sgRDo/CWEQK06PZf2YiJXdr1Wd+kuKiMgL/6l0FRlYP/QIDAQAB";
//	    	//
//	    	RSA rsa = new RSA(PRIVATE_KEY, Pub_KEY);
////
//	    	String a = "2324324234";
//	    	
//	    	
//	    	
//	    	byte[] encrypt = rsa.encrypt(StrUtil.bytes(a, CharsetUtil.CHARSET_UTF_8), KeyType.PrivateKey);
//	    	System.err.println(new String(encrypt));
//	    	String encodeHexStr = HexUtil.encodeHexStr(encrypt);
//	    	System.err.println(encodeHexStr);
//	    	
//	    	byte[] aByte = HexUtil.decodeHex(encodeHexStr);
//	    	byte[] decrypt = rsa.decrypt(aByte, KeyType.PublicKey);
//	    	
//	    	System.err.println(new String(decrypt));
//	    	
//	    	
//	    	RSA rsa = new RSA();
//
//	    	//获得私钥
//	    	rsa.getPrivateKey();
//	    	String privateKeyBase64 = rsa.getPrivateKeyBase64();
//	    	System.err.println(new String(privateKeyBase64));
//	    	//获得公钥
//	    	PublicKey publicKey = rsa.getPublicKey();
//	    	
//	    	String publicKeyBase64 = rsa.getPublicKeyBase64();
//	    	System.err.println(new String(publicKeyBase64));
//	    	KeyType publickey = KeyType.PublicKey;
	    	
//	    	//公钥加密，私钥解密
//	    	byte[] encrypt = rsa.encrypt(StrUtil.bytes("我是一段测试aaaa", CharsetUtil.CHARSET_UTF_8), publickey);
//	    	System.err.println(Base64.encodeBase64String(encrypt));
//	    	
//	    	byte[] decrypt = rsa.decrypt(encrypt, KeyType.PrivateKey);
//	    	System.err.println(new String(decrypt));
//	    	
//	    	
	    	//Junit单元测试
	    	//Assert.assertEquals("我是一段测试aaaa", StrUtil.str(decrypt, CharsetUtil.CHARSET_UTF_8));

	    	//私钥加密，公钥解密
//	    	byte[] encrypt2 = rsa.encrypt(StrUtil.bytes("我是一段测试aaaa", CharsetUtil.CHARSET_UTF_8), KeyType.PrivateKey);
//	    	byte[] decrypt2 = rsa.decrypt(encrypt2, publickey);
	    	
	    	
		}
   
}
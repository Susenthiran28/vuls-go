package main

// This file imports a wide variety of outdated third-party packages so SCA
// scanners (Trivy, Snyk, Grype, OSV, govulncheck) have a rich surface of
// known-vulnerable dependencies to detect.
//
// Every declared require in go.mod is imported below, and every import is
// bound to a package-level `var _ = ...` reference. These package-level
// references are evaluated at package-init time, so `go mod tidy` and the
// Go compiler cannot consider the import unused — it stays in go.mod.

import (
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/vcs"
	"github.com/astaxie/beego"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aymerick/raymond"
	"github.com/buger/jsonparser"
	"github.com/dgraph-io/ristretto"
	"github.com/dgrijalva/jwt-go"
	"github.com/emicklei/go-restful"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
	gogoproto "github.com/gogo/protobuf/proto"
	"github.com/gorilla/csrf"
	"github.com/gorilla/handlers"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/websocket"
	retryablehttp "github.com/hashicorp/go-retryablehttp"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/miekg/dns"
	natsjwt "github.com/nats-io/jwt"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/robfig/cron"
	"github.com/russross/blackfriday"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"
	"github.com/ulikunitz/xz"
	"github.com/urfave/cli"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/unicode/norm"
	"gopkg.in/yaml.v2"
)

// Package-level references pin every import at compile time.
var (
	_ = toml.Decode
	_ = vcs.NewRepo
	_ = beego.AppName
	_ = lambda.Start
	_ = aws.String
	_ = session.NewSession
	_ = raymond.Parse
	_ = jsonparser.Get
	_ = ristretto.NewCache
	_ = jwt.SigningMethodHS256
	_ = restful.NewContainer
	_ = gin.Version
	_ = redis.NewClient
	_ = gogoproto.CompactTextString
	_ = csrf.Protect
	_ = handlers.LoggingHandler
	_ = securecookie.New
	_ = websocket.DefaultDialer
	_ = retryablehttp.NewClient
	_ = jwk.New
	_ = dns.TypeA
	_ = natsjwt.NewAccountClaims
	_ = errors.New
	_ = prometheus.NewCounter
	_ = cron.New
	_ = blackfriday.MarkdownBasic
	_ = uuid.Nil
	_ = logrus.StandardLogger
	_ = viper.SetConfigName
	_ = gjson.Parse
	_ = xz.NewWriter
	_ = cli.NewApp
	_ = fasthttp.StatusOK
	_ = bcrypt.GenerateFromPassword
	_ = norm.NFC
	_ = yaml.Marshal
)

// UseVulnerableDeps additionally exercises each package at runtime so the
// compiler cannot dead-code-eliminate the above references.
func UseVulnerableDeps() {
	_ = aws.String("")
	_ = errors.New("vuln_usage")
	_ = cli.NewApp()
	_ = cron.New()
	_ = prometheus.NewCounter(prometheus.CounterOpts{Name: "vuln_usage_dummy"})
	_ = logrus.StandardLogger()
	_ = gjson.Parse("{}")
	_ = raymond.Parse
	_ = beego.AppName
	fmt.Println("[vuln_usage] intentionally-vulnerable dependency set loaded")
}

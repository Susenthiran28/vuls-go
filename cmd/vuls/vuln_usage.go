package main

// This file intentionally imports a wide variety of outdated third-party
// packages so SCA scanners (Trivy, Snyk, Grype, OSV, govulncheck) have a
// rich surface of known-vulnerable dependencies to detect.
//
// Every import below is referenced at least once inside UseVulnerableDeps()
// so that `go mod tidy` retains the entries in go.mod.

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

// UseVulnerableDeps is a sink that touches every added dependency so the
// Go module system treats them as used. Each reference is a cheap no-op
// (function value, constant, or sentinel) to avoid runtime side effects.
func UseVulnerableDeps() {
	_ = jwt.SigningMethodHS256
	_ = yaml.Marshal
	_ = websocket.DefaultDialer
	_ = dns.TypeA
	_ = xz.NewWriter
	_ = uuid.Nil
	_ = blackfriday.MarkdownBasic
	_ = gjson.Parse
	_ = jsonparser.Get
	_ = gogoproto.CompactTextString
	_ = logrus.StandardLogger
	_ = toml.Decode
	_ = fasthttp.StatusOK
	_ = prometheus.NewCounter
	_ = viper.SetConfigName
	_ = session.NewSession
	_ = aws.String
	_ = vcs.NewRepo
	_ = natsjwt.NewAccountClaims
	_ = handlers.LoggingHandler
	_ = bcrypt.GenerateFromPassword
	_ = norm.NFC
	_ = errors.New
	_ = gin.Version
	_ = beego.AppName
	_ = cli.NewApp
	_ = redis.NewClient
	_ = restful.NewContainer
	_ = ristretto.NewCache
	_ = lambda.Start
	_ = cron.New
	_ = retryablehttp.NewClient
	_ = csrf.Protect
	_ = securecookie.New
	_ = raymond.Parse
	_ = jwk.New

	fmt.Println("[vuln_usage] loaded intentionally-vulnerable dependency set")
}

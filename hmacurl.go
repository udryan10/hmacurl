package main

import (
	"./canonicalRequest"
	"./signString"
	"./signature"
	"./utilities"
	"./validation"
	"bytes"
	"fmt"
	"github.com/jessevdk/go-flags"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// positional argument
type Url struct {
	Url string `positional-arg-name:"url"`
}

// setup flags
var opts struct {
	Request string `short:"X" long:"request" default:"GET" description:"the http method to use" value-name:"GET|POST"`

	Data string `short:"d" long:"data" default:"" description:"for POST requests, the data to be uploaded as the body. Used if -f is not provided." value-name:"'my string body'"`

	File string `short:"f" long:"file" default:"" description:"for POST requests, the file to be uploaded as the body. Used if -d is not provided" value-name:"./file.txt"`

	Headers map[string]string `short:"H" optional:"true" long:"header" description:"Extra header(s) to include in the request when sending HTTP to a server. You may specify any number of extra headers. "value-name:"'Content-Type: application/json'"`

	CurlOnly bool `long:"curl-only" default:"false" description:"If specified, will only print out a curl command - not actually run a request"`

	AccessKey string `short:"a" long:"access-key" default:"" description:"The access Key to use in HMAC signing. Can also be specified as an environment variable(export HMACURL_ACCESS_KEY='fasdf')"`

	SecretKey string `short:"s" long:"secret-key" default:"" description:"The secret Key to use in HMAC signing. Can also be specified as an environment variable(export HMACURL_SECRET_KEY='fasdf')"`

	Debug bool `long:"debug" default:"false" description:"Whether to output debug information"`

	// remaining positional args
	Args Url `positional-args:"true" required:"true"`
}

// will run before main() used to parse our flags
func init() {
	_, err := flags.Parse(&opts)
	// help call
	if err != nil {
		os.Exit(0)
	}
}

func main() {

	var accessKey string
	var secretKey string

	// if we werent provided these arguments, pull from environment
	if opts.AccessKey == "" {
		if os.Getenv("HMACURL_ACCESS_KEY") == "" {
			fmt.Println("Please provide access key via argument or environment variable HMACURL_ACCESS_KEY")
			os.Exit(3)
		} else {
			accessKey = os.Getenv("HMACURL_ACCESS_KEY")
		}
	} else {
		accessKey = opts.AccessKey
	}
	if opts.SecretKey == "" {
		if os.Getenv("HMACURL_SECRET_KEY") == "" {
			fmt.Println("Please provide secret key via argument or environment variable HMACURL_SECRET_KEY")
			os.Exit(3)
		} else {
			secretKey = os.Getenv("HMACURL_SECRET_KEY")
		}
	} else {
		secretKey = opts.SecretKey
	}

	if validation.Method(opts.Request) == false {
		fmt.Printf("method %s is invalid\n", opts.Request)
		os.Exit(1)
	}

	urlString, err := url.Parse(opts.Args.Url)

	if err != nil {
		fmt.Printf("Invalid url %s\n", opts.Args.Url)
		os.Exit(2)
	}

	var payload string = ""
	if opts.Request == "POST" {
		if opts.Data != "" {
			payload = opts.Data
		} else if opts.File != "" {
			fileContents, err := ioutil.ReadFile(opts.File)
			if err != nil {
				panic(err)
			}
			// reading from file seems to put a newline at end - trim this
			payload = strings.TrimSuffix(string(fileContents[:]), "\n")
		}
	}
	//requestTime := time.Now().UTC()
  layout := "2006-01-02T15:04:05.000Z"
  str := "2015-05-10T13:45:26.000Z"
  requestTime, err := time.Parse(layout, str)
	//requestTime := time.Now().UTC()

	host, _, err := net.SplitHostPort(urlString.Host)
	// likely no port
	if err != nil {
		host = urlString.Host
	}
	hostShort := strings.Split(host, ".")[0]

	// setup headers
	headerMap := map[string]string{"x-amz-date": requestTime.Format("20060102T150405Z")}

	// add headers passed in from -H options to headerMap
	for k, v := range opts.Headers {
		headerMap[strings.ToLower(k)] = strings.ToLower(v)
	}

	// if we were not given a Content-Type, use the default standard
	if _, ok := headerMap["content-type"]; !ok {
		headerMap["content-type"] = "application/octet-stream"
	}

	// where we start the signing process - pass in http method, url, headers and payload. for GET requests payload should be ""
	canonicalString := canonicalRequest.FormatCanonicalString(opts.Request, urlString, headerMap, payload)
	if opts.Debug == true {
		fmt.Println("Canonical String:")
		fmt.Println(canonicalString)
		fmt.Println("================")
	}
	canonicalStringHashed := utilities.DataToSha256Encoded([]byte(canonicalString))
	if opts.Debug == true {
		fmt.Println("Canonical String Hashed:")
		fmt.Println(canonicalStringHashed)
		fmt.Println("================")
	}
	stringToSign := signString.StringToSign(requestTime, canonicalStringHashed, hostShort)
	if opts.Debug == true {
		fmt.Println("String to sign:")
		fmt.Println(stringToSign)
		fmt.Println("================")
	}

	signature := signature.CalculateSignature(requestTime, stringToSign, hostShort, secretKey)
	headerMap["Authorization"] = utilities.GenerateSignedHeader(accessKey, signature, hostShort, requestTime.Format("20060102"), canonicalRequest.FormatSignedHeaders(headerMap))
	if opts.Debug == true {
		fmt.Println("signature:")
		fmt.Println(headerMap["Authorization"])
		fmt.Println("================")
	}

	// signing process is complete start http calls

	// if we had a flag to only output the curl command, dump that and be done
	if opts.CurlOnly == true {
		headerStringBuild := ""
		for k, v := range headerMap {
			headerStringBuild += fmt.Sprintf(" %s '%s:%s'", "-H", k, v)
		}
		if opts.Request == "POST" {
			fmt.Printf("curl -X%s %s %s -v -d'%s'", opts.Request, headerStringBuild, urlString, payload)
		} else if opts.Request == "GET" {
			fmt.Printf("curl -X%s %s %s -v", opts.Request, headerStringBuild, urlString)
		}
		fmt.Println()
		os.Exit(0)
	}

	// make either a GET Request or POST Request
	if opts.Request == "GET" {
		client := &http.Client{}
		req, err := http.NewRequest("GET", urlString.String(), nil)
		// add headers to request
		for k, v := range headerMap {
			req.Header.Add(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("error in http call")
			os.Exit(4)
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		fmt.Println(string(body[:]))
	} else if opts.Request == "POST" {
		client := &http.Client{}
		req, err := http.NewRequest("POST", urlString.String(), bytes.NewBufferString(payload))
		// add headers to request
		for k, v := range headerMap {
			req.Header.Add(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("error in http call")
			os.Exit(4)
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		fmt.Println(string(body[:]))
	}
}
